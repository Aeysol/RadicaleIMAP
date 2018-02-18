# RadicaleIMAP IMAP authentication plugin for Radicale.
# Copyright (C) 2017 Unrud <unrud@openaliasbox.org>
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

import imaplib
import ssl
import sys

from radicale.auth import BaseAuth

VERSION = "2.0.0"


class Auth(BaseAuth):
    """Authenticate user with IMAP.

    Configuration:

    [auth]
    type = radicale_imap
    imap_host = imap.server.tld
    imap_ssl_type = SSL

    """

    def is_authenticated(self, user, password):
        host = ""
        if self.configuration.has_option("auth", "imap_host"):
            host = self.configuration.get("auth", "imap_host")
        ssl_type = ""
        if self.configuration.has_option("auth", "imap_ssl_type"):
            ssl_type = str.upper(self.configuration.get("auth", "imap_ssl_type"))
        try:
            if ":" in host:
                address, port = host.rsplit(":", maxsplit=1)
            else:
                address, port = host, 143
            address, port = address.strip("[] "), int(port)
        except ValueError as e:
            raise RuntimeError("Failed to parse address %r: %s" % (host, e)) from e
        if sys.version_info < (3, 4) and ssl_type:
            raise RuntimeError("Secure IMAP is not available in Python < 3.4")
        try:
            if ssl_type.upper() == "SSL":
                connection = imaplib.IMAP4_SSL(host=address, port=port)
            elif ssl_type.upper() == "STARTTLS":
                connection = imaplib.IMAP4(host=address, port=port)
                try:
                    if sys.version_info < (3, 4):
                        connection.starttls()
                    else:
                        connection.starttls(ssl.create_default_context())
                except (imaplib.IMAP4.error, ssl.CertificateError) as e:
                    if ssl_type in ("SSL", "STARTTLS"):
                        raise self.logger.debug("Failed to establish secure connection: %s", e, exc_info=True)
            else:
                raise RuntimeError("Attribute imap_ssl_type has an invalid value: %s" % ssl_type)
            try:
                connection.login(user, password)
            except imaplib.IMAP4.error as e:
                self.logger.debug("IMAP authentication failed: %s", e, exc_info=True)
                return False
            connection.logout()
            return True
        except (OSError, imaplib.IMAP4.error) as e:
            raise RuntimeError("Failed to communicate with IMAP server %r: ""%s" % (host, e)) from e
