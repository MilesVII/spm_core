# Seventh Password Manager (Core)
Password manager that provides blake2b hashsums with unique presentations as passwords. Uses [monocypher](http://monocypher.org/) (Which is really cool) to generate blake2b hashsums and wipe memory.

The idea is to use some simple words like your favourite (probably unsafe) master-password and word that decribes place where you want to login (named **authorization target**), mix them up and generate some secure password, which can be generated only with those words. So, every time you enter the same words into program, it will generate the same password.

Use of hashfunction allows not to store passwords data and generate it on every execution: you just enter your master-password and authorization target (something like "github" or "mymail@gmail.com" or "you-know-where"), program processes these strings and generates password using predefined set of characters. The password is saved to your clipboard then and wiped from memory.

## How to use
### Install:
Copy spm.exe wherever you want and add it's path to PATH environment variable (if you wish). That's it!

### Use:
Just type something like `spm supersecretpassword github` in your command prompt and generated password will be copied straight to your clipboard. You can even create a shortcut that will run this command in a few clicks, though it is not recommended.

#### (Optional) Custom password character sets
By default, passwords generated by program will consist if upper- and lowercase latin letters, numbers and characters "!@&#". **You can use your own set of characters:** just create file "spm_cc.txt" near the executable and enter them in first line of the file. Program will automatically detect file and use provided set. Note that **character set is order-sensitive**. Also, you are **restricted to use only US-ASCII characters**.

#### (Optional) Safety check for authorization target
If you are unsure if you will remember your authorization target exactly, you can use safety check. To do so, you should add your auth target to the list of known targets: `spm supersecretpassword github -r`. This will make program run as usual, except it will store salted hashsum of your auth target in ".spm_at" file. 
Then, when you will be requesting your password, just use `-c` flag: `spm supersecretpassword github -c`, and program will check if provided target was used before. If not, it will show message "Authorization target unknown" and won't do anything.

## Notes:
* Provided data won't be stored on your disk in any way. The only exception is salted hashsum that will be stored in ".spm_at" file if you explicitly specify this with `-r` flag
* Master password and auth targets are case-sensitive
* If you use custom character set, keep in mind that it is order-sensitive
* If you change your password character set, you will lose the chance to restore previously generated passwords. Your will also have to register auth targets again
* Length of generated passwords is fixed to 16 characters. Technically, it is possible to generate passwords that 4/8/32/64-characters long, but this feature is currently disabled for more consistent output

## Disclaimer
Seventh Password Manager is provided by Miles Seventh "as is" and "with all faults". Developer makes no representations or warranties of any kind concerning the safety, suitability, inaccuracies, typographical errors, or other harmful components of this software. You are solely responsible for the protection of your equipment and backup of your data, and the Developer will not be liable for any damages you may suffer in connection with using, modifying, or distributing this software.

License: [CC-BY-NC-SA](https://creativecommons.org/licenses/by-nc-sa/4.0/)