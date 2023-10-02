# cipher-privy-script-injection

This repository demonstrated a cross site script injection on [cipher.rip](https://cipher.rip).  It has since been fixed.

Posts created with this [payload](payload.html) would inject this [script](script.js) into browsers that rendered the post.

The script performed a recovery operation on [privy.io](https://privy.io), decrypted + combined the shares, and drained the user's wallet.
