# PasswordCheck

This is a simple Swift program written for iOS that asks for password and
verify if it's correct or not. This binary is used for testing the Decai
decompiler using different AI models.

## Testing

When you open the binary just using R2 password check, it will prompt you to
run the R2 script. That it's a companion file that is next to the binary. This
will basically analyze the target function, seek there, and set up the CHI
options to get the right output for Swift.

## Other Languages

It is important to understand how to change the options in the CLI so you can
use the `decai -m model` or the `decai -p provider` to change the selected AI
model to use.

But also we can use the `decai -e lang=swift` for example, but we can also
select any other language to decompile to `bash`, `php`, `perl` and `ruby` for
example.

Any language will work.
