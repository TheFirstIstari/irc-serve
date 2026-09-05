# Spec Tracking

## References
- RFC 1459: https://datatracker.ietf.org/doc/html/rfc1459
- Modern IRC: https://modern.ircdocs.horse/
- IRCv3: https://ircv3.net/
- Tools (ii): https://tools.suckless.org/ii/
- Example servers: https://github.com/squidowl/halloy, https://github.com/Yengas/rust-chat-server

## Implementation Status (TDD tracking)
| Feature | RFC / Modern | Status | Issue |
|---------|-------------|--------|-------|
| Basic commands (NICK, USER, JOIN, PRIVMSG) | RFC 1459 | Skeleton | #1 |
| IRCv3 message tags | IRCv3 | Planned | #2 |
| Federation handshake | Custom | Design | #3 |
| Auto-scaling / load balance | Custom | Design | #4 |
