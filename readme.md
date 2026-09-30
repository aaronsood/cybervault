**CyberVault**

simple terminal password manager built in c#. encrypts your logins locally using aes-256-gcm and pbkdf2 key derivation so you don't gotta rely on cloud tools.

features

aes gcm encryption for vault entries

pbkdf2 key derivation (600k iterations)

masked password typing

password generator built in

how to use

option 1: prebuilt binaries
grab the build for your platform from releases and run it:

mac / linux (chmod first)

chmod +x CyberVault
./CyberVault

option 2: build it yourself
need the .net sdk installed.

git clone https://github.com/aaronsood/cybervault.git
cd cybervault
dotnet run

note:

everything stays local in vault.dat. dont push your master.txt or vault.dat files anywhere.
