import email
import hashlib
import os
path = './'
listing = os.listdir(path)

for file in listing:
    if file.lower().endswith(".eml"):
        msg = email.message_from_file(open(file))
        attachments = msg.walk()
        for part in msg.walk():
            fname = part.get_filename()
            ctype = part.get_content_type()

            if fname is not None:
                decodedAttachment = part.get_payload(decode=True)
                f = hashlib.sha256(decodedAttachment).hexdigest()
                print(f"{fname} -> {f}")

            elif ctype == "text/plain" or ctype == "text/html":
                body = part.get_payload(decode=True).decode(errors="replace")
