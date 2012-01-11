@ECHO OFF

mkdir \\%1\c$\tmp
copy chwp.exe \\%1\c$\tmp
copy cat-owned.bmp \\%1\c$\tmp
wmic /node:"%1" /user:bob.carroll process call create "cmd.exe /c c:\tmp\chwp.exe \tmp\cat-owned.bmp > c:\tmp\out.txt"