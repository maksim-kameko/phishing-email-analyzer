import email
import hashlib
import os
path = './'
listing = os.listdir(path)

for file in listing:
    if file.lower().endswith(".eml"):
        msg = email.message_from_file(open(file))
        attachments = msg.walk()
        for attachment in attachments:
            fnam = attachment.get_filename()
            if fnam is None:
                continue
            decodedFile = attachment.get_payload(decode=True)
            f = hashlib.sha256(decodedFile).hexdigest()
            print(f"{fnam} -> {f}")
            decodedFile = decodedFile.decode(errors="replace")
            print(f"{fnam} -> {decodedFile}")