# Copyright 2014-2021 The Matrix.org Foundation C.I.C.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import logging
import random
from typing import TYPE_CHECKING, Any, Dict, Optional, Tuple

from synapse.api.constants import LoginType
from synapse.api.errors import Codes, SynapseError
from synapse.api.ratelimiting import Ratelimiter
from synapse.config.emailconfig import ThreepidBehaviour
from synapse.handlers.ui_auth import UIAuthSessionDataConstants
from synapse.http.server import HttpServer
from synapse.http.servlet import (
    RestServlet,
    assert_params_in_dict,
    parse_json_object_from_request,
)
from synapse.http.site import SynapseRequest
from synapse.metrics import threepid_send_requests
from synapse.push.mailer import Mailer
from synapse.rest.client._base import client_patterns, interactive_auth_handler
from synapse.rest.well_known import WellKnownBuilder
from synapse.types import JsonDict, UserID
from synapse.util.msisdn import phone_number_to_msisdn
from synapse.util.stringutils import assert_valid_client_secret, random_string
from synapse.util.threepids import canonicalise_email, check_3pid_allowed

if TYPE_CHECKING:
    from synapse.server import HomeServer

logger = logging.getLogger(__name__)


class EmailLogin3pidRequestTokenRestServlet(RestServlet):
    PATTERNS = client_patterns(
        "/login_3pid/email/requestToken$", releases=(), unstable=True
    )

    def __init__(self, hs: "HomeServer"):
        """
        Args:
            hs (synapse.server.HomeServer): server
        """
        super().__init__()
        self.hs = hs
        self.identity_handler = hs.get_identity_handler()
        self.config = hs.config

        self._address_ratelimiter = Ratelimiter(
            store=hs.get_datastore(),
            clock=hs.get_clock(),
            rate_hz=self.hs.config.ratelimiting.rc_login_address.per_second,
            burst_count=self.hs.config.ratelimiting.rc_login_address.burst_count,
        )

        if self.hs.config.email.threepid_behaviour_email == ThreepidBehaviour.LOCAL:
            self.mailer = Mailer(
                hs=self.hs,
                app_name=self.config.email.email_app_name,
                template_html=self.config.email.email_registration_template_html,
                template_text=self.config.email.email_registration_template_text,
            )

    async def on_POST(self, request: SynapseRequest) -> Tuple[int, JsonDict]:
        self._address_ratelimiter.ratelimit(None, request.getClientIP())
        if self.hs.config.email.threepid_behaviour_email == ThreepidBehaviour.OFF:
            if (
                self.hs.config.email.local_threepid_handling_disabled_due_to_email_config
            ):
                logger.warning(
                    "Email registration has been disabled due to lack of email config"
                )
            raise SynapseError(
                400, "Email-based registration has been disabled on this server"
            )
        body = parse_json_object_from_request(request)

        assert_params_in_dict(body, ["client_secret", "email", "send_attempt"])

        # Extract params from body
        client_secret = body["client_secret"]
        assert_valid_client_secret(client_secret)

        # For emails, canonicalise the address.
        # We store all email addresses canonicalised in the DB.
        # (See on_POST in EmailThreepidRequestTokenRestServlet
        # in synapse/rest/client/v2_alpha/account.py)
        try:
            email = canonicalise_email(body["email"])
        except ValueError as e:
            raise SynapseError(400, str(e))
        send_attempt = body["send_attempt"]
        next_link = body.get("next_link")  # Optional param

        if not check_3pid_allowed(self.hs, "email", email):
            raise SynapseError(
                403,
                "Your email domain is not authorized to register on this server",
                Codes.THREEPID_DENIED,
            )

        existing_user_id = await self.hs.get_datastore().get_user_id_by_threepid(
            "email", email
        )

        if existing_user_id is None:
            if self.hs.config.server.request_token_inhibit_3pid_errors:
                # Make the client think the operation succeeded. See the rationale in the
                # comments for request_token_inhibit_3pid_errors.
                # Also wait for some random amount of time between 100ms and 1s to make it
                # look like we did something.
                await self.hs.get_clock().sleep(random.randint(1, 10) / 10)
                return 200, {"sid": random_string(16)}

            raise SynapseError(400, "User not found", Codes.THREEPID_IN_USE)

        if self.config.email.threepid_behaviour_email == ThreepidBehaviour.REMOTE:
            assert self.hs.config.registration.account_threepid_delegate_email

            # Have the configured identity server handle the request
            ret = await self.identity_handler.requestEmailToken(
                self.hs.config.registration.account_threepid_delegate_email,
                email,
                client_secret,
                send_attempt,
                next_link,
            )
        else:
            # Send registration emails from Synapse
            sid = await self.identity_handler.send_threepid_validation(
                email,
                client_secret,
                send_attempt,
                self.mailer.send_registration_mail,
                next_link,
            )

            # Wrap the session id in a JSON object
            ret = {"sid": sid}

        threepid_send_requests.labels(type="email", reason="login").observe(
            send_attempt
        )

        return 200, ret


class MsisdnLogin3pidRequestTokenRestServlet(RestServlet):
    PATTERNS = client_patterns(
        "/login_3pid/msisdn/requestToken$", releases=(), unstable=True
    )

    def __init__(self, hs: "HomeServer"):
        """
        Args:
            hs (synapse.server.HomeServer): server
        """
        super().__init__()
        self.hs = hs
        self.identity_handler = hs.get_identity_handler()

        self._address_ratelimiter = Ratelimiter(
            store=hs.get_datastore(),
            clock=hs.get_clock(),
            rate_hz=self.hs.config.ratelimiting.rc_login_address.per_second,
            burst_count=self.hs.config.ratelimiting.rc_login_address.burst_count,
        )

    async def on_POST(self, request: SynapseRequest) -> Tuple[int, JsonDict]:
        self._address_ratelimiter.ratelimit(None, request.getClientIP())

        body = parse_json_object_from_request(request)

        assert_params_in_dict(
            body, ["client_secret", "country", "phone_number", "send_attempt"]
        )
        client_secret = body["client_secret"]
        country = body["country"]
        phone_number = body["phone_number"]
        send_attempt = body["send_attempt"]
        next_link = body.get("next_link")  # Optional param

        msisdn = phone_number_to_msisdn(country, phone_number)

        if not check_3pid_allowed(self.hs, "msisdn", msisdn):
            raise SynapseError(
                403,
                "Phone numbers are not authorized to register on this server",
                Codes.THREEPID_DENIED,
            )

        existing_user_id = await self.hs.get_datastore().get_user_id_by_threepid(
            "msisdn", msisdn
        )

        if existing_user_id is None:
            if self.hs.config.server.request_token_inhibit_3pid_errors:
                # Make the client think the operation succeeded. See the rationale in the
                # comments for request_token_inhibit_3pid_errors.
                # Also wait for some random amount of time between 100ms and 1s to make it
                # look like we did something.
                await self.hs.get_clock().sleep(random.randint(1, 10) / 10)
                return 200, {"sid": random_string(16)}

            raise SynapseError(400, "User not found", Codes.THREEPID_IN_USE)

        if not self.hs.config.registration.account_threepid_delegate_msisdn:
            logger.warning(
                "No upstream msisdn account_threepid_delegate configured on the server to "
                "handle this request"
            )
            raise SynapseError(
                400, "Registration by phone number is not supported on this homeserver"
            )

        ret = await self.identity_handler.requestMsisdnToken(
            self.hs.config.registration.account_threepid_delegate_msisdn,
            country,
            phone_number,
            client_secret,
            send_attempt,
            next_link,
        )

        threepid_send_requests.labels(type="msisdn", reason="login").observe(
            send_attempt
        )

        return 200, ret


class Login3pidRestServlet(RestServlet):
    PATTERNS = client_patterns("/login_3pid$", releases=(), unstable=True)
    REFRESH_TOKEN_PARAM = "refresh_token"

    def __init__(self, hs: "HomeServer"):
        super().__init__()
        self.hs = hs

        self.store = hs.get_datastore()

        self._refresh_tokens_enabled = (
            hs.config.registration.refreshable_access_token_lifetime is not None
        )

        self.clock = hs.get_clock()

        self.auth_handler = self.hs.get_auth_handler()
        self.registration_handler = hs.get_registration_handler()

        self._well_known_builder = WellKnownBuilder(hs)
        self._address_ratelimiter = Ratelimiter(
            store=hs.get_datastore(),
            clock=hs.get_clock(),
            rate_hz=self.hs.config.ratelimiting.rc_login_address.per_second,
            burst_count=self.hs.config.ratelimiting.rc_login_address.burst_count,
        )
        self._account_ratelimiter = Ratelimiter(
            store=hs.get_datastore(),
            clock=hs.get_clock(),
            rate_hz=self.hs.config.ratelimiting.rc_login_account.per_second,
            burst_count=self.hs.config.ratelimiting.rc_login_account.burst_count,
        )

    def on_GET(self, request: SynapseRequest) -> Tuple[int, JsonDict]:
        flows = []

        flows.append({"type": LoginType.MSISDN})
        flows.append({"type": LoginType.EMAIL_IDENTITY})

        return 200, {"flows": flows}

    @interactive_auth_handler
    async def on_POST(self, request: SynapseRequest) -> Tuple[int, JsonDict]:
        login_submission = parse_json_object_from_request(request)

        # Check to see if the client requested a refresh token.
        client_requested_refresh_token = login_submission.get(
            Login3pidRestServlet.REFRESH_TOKEN_PARAM, False
        )
        if not isinstance(client_requested_refresh_token, bool):
            raise SynapseError(400, "`refresh_token` should be true or false.")

        should_issue_refresh_token = (
            self._refresh_tokens_enabled and client_requested_refresh_token
        )

        if "type" not in login_submission:
            self._address_ratelimiter.ratelimit(
                None, request.getClientIP(), update=False
            )

            session_id = self.auth_handler.get_session_id(login_submission)
            logged_user_id = None
            if session_id:
                logged_user_id = await self.auth_handler.get_session_data(
                    session_id, UIAuthSessionDataConstants.REQUEST_USER_ID, None
                )
                if logged_user_id is not None:
                    raise SynapseError(403, "Already logged for this session")

            auth_result, params, session_id = await self.auth_handler.check_ui_auth(
                [[LoginType.MSISDN], [LoginType.EMAIL_IDENTITY]],
                request,
                login_submission,
                "login into account",
            )

            raise SynapseError(400, "Missing JSON keys.")

        try:
            if (
                login_submission["type"] == LoginType.MSISDN
                or login_submission["type"] == LoginType.EMAIL_IDENTITY
            ):
                self._address_ratelimiter.ratelimit(
                    None, request.getClientIP(), update=False
                )
                session_id = self.auth_handler.get_session_id(login_submission)
                logged_user_id = None
                if session_id:
                    logged_user_id = await self.auth_handler.get_session_data(
                        session_id, UIAuthSessionDataConstants.REQUEST_USER_ID, None
                    )
                    if logged_user_id is not None:
                        raise SynapseError(403, "Already logged for this session")

                login_type = login_submission["type"]
                auth_result, params, session_id = await self.auth_handler.check_ui_auth(
                    [[login_type]],
                    request,
                    login_submission,
                    "login into account",
                )
                # Check that we're not trying to login a denied 3pid.
                if auth_result:
                    if login_type in auth_result:
                        medium = auth_result[login_type]["medium"]
                        address = auth_result[login_type]["address"]

                        if not check_3pid_allowed(self.hs, medium, address):
                            raise SynapseError(
                                403,
                                "Third party identifiers (email/phone numbers)"
                                + " are not authorized on this server",
                                Codes.THREEPID_DENIED,
                            )

                        # For emails, canonicalise the address.
                        # We store all email addresses canonicalised in the DB.
                        # (See on_POST in EmailThreepidRequestTokenRestServlet
                        # in synapse/rest/client/v2_alpha/account.py)
                        if medium == "email":
                            try:
                                address = canonicalise_email(address)
                            except ValueError as e:
                                raise SynapseError(400, str(e))

                        logged_user_id = await self.store.get_user_id_by_threepid(
                            medium, address
                        )
                if logged_user_id is None:
                    raise SynapseError(
                        400,
                        "User not exists",
                        Codes.THREEPID_IN_USE,
                    )

                result = await self._complete_login(
                    logged_user_id,
                    login_submission,
                    should_issue_refresh_token=should_issue_refresh_token,
                )

                await self.auth_handler.set_session_data(
                    session_id,
                    UIAuthSessionDataConstants.REQUEST_USER_ID,
                    logged_user_id,
                )
            else:
                raise SynapseError(400, "Only msisdn and email allowed")
        except KeyError:
            raise SynapseError(400, "Missing JSON keys.")

        well_known_data = self._well_known_builder.get_well_known()
        if well_known_data:
            result["well_known"] = well_known_data
        return 200, result

    async def _complete_login(
        self,
        user_id: str,
        login_submission: JsonDict,
        create_non_existent_users: bool = False,
        ratelimit: bool = True,
        auth_provider_id: Optional[str] = None,
        should_issue_refresh_token: bool = False,
        auth_provider_session_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Called when we've successfully authed the user and now need to
        actually login them in (e.g. create devices). This gets called on
        all successful logins.

        Applies the ratelimiting for successful login attempts against an
        account.

        Args:
            user_id: ID of the user to register.
            login_submission: Dictionary of login information.
            create_non_existent_users: Whether to create the user if they don't
                exist. Defaults to False.
            ratelimit: Whether to ratelimit the login request.
            auth_provider_id: The SSO IdP the user used, if any.
            should_issue_refresh_token: True if this login should issue
                a refresh token alongside the access token.
            auth_provider_session_id: The session ID got during login from the SSO IdP.

        Returns:
            result: Dictionary of account information after successful login.
        """

        # Before we actually log them in we check if they've already logged in
        # too often. This happens here rather than before as we don't
        # necessarily know the user before now.
        if ratelimit:
            await self._account_ratelimiter.ratelimit(None, user_id.lower())

        if create_non_existent_users:
            canonical_uid = await self.auth_handler.check_user_exists(user_id)
            if not canonical_uid:
                canonical_uid = await self.registration_handler.register_user(
                    localpart=UserID.from_string(user_id).localpart
                )
            user_id = canonical_uid

        device_id = login_submission.get("device_id")
        initial_display_name = login_submission.get("initial_device_display_name")
        (
            device_id,
            access_token,
            valid_until_ms,
            refresh_token,
        ) = await self.registration_handler.register_device(
            user_id,
            device_id,
            initial_display_name,
            auth_provider_id=auth_provider_id,
            should_issue_refresh_token=should_issue_refresh_token,
            auth_provider_session_id=auth_provider_session_id,
        )

        result: Dict[str, Any] = {
            "user_id": user_id,
            "access_token": access_token,
            "home_server": self.hs.hostname,
            "device_id": device_id,
        }

        if valid_until_ms is not None:
            expires_in_ms = valid_until_ms - self.clock.time_msec()
            result["expires_in_ms"] = expires_in_ms

        if refresh_token is not None:
            result["refresh_token"] = refresh_token

        return result


def register_servlets(hs: "HomeServer", http_server: HttpServer) -> None:
    Login3pidRestServlet(hs).register(http_server)
    EmailLogin3pidRequestTokenRestServlet(hs).register(http_server)
    MsisdnLogin3pidRequestTokenRestServlet(hs).register(http_server)
