# rgbypass
[RebirthGuard](https://github.com/chztbby/RebirthGuard) Anti-Cheat Bypass.

Works by overwriting a trusted function with shellcode (bypasses 1), setting the page protection to PAGE_EXECUTE_READ, which is not checked (bypasses 2), and simply calling LoadLibraryExA after a no operation instruction (bypasses 3)


![image](https://github.com/user-attachments/assets/e3e9adb5-866a-46aa-a939-bf29adb16864)
