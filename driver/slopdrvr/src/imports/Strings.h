#pragma once
#include <ntifs.h>

__forceinline char locase_a(char c)
{
    if ((c >= 'A') && (c <= 'Z'))
        return c + 0x20;
    else
        return c;
}

inline int _strcmpi_a(const char* s1, const char* s2)
{
    char c1, c2;

    if (s1 == s2)
        return 0;

    if (s1 == 0)
        return -1;

    if (s2 == 0)
        return 1;

    do {
        c1 = locase_a(*s1);
        c2 = locase_a(*s2);
        s1++;
        s2++;
    } while ((c1 != 0) && (c1 == c2));

    return (int)(c1 - c2);
}

inline wchar_t locase_w(wchar_t c)
{
    if ((c >= 'A') && (c <= 'Z'))
        return c + 0x20;
    else
        return c;
}

inline int _strcmpi_w(const wchar_t* s1, const wchar_t* s2)
{
    wchar_t c1, c2;

    if (s1 == s2)
        return 0;

    if (s1 == 0)
        return -1;

    if (s2 == 0)
        return 1;

    do {
        c1 = locase_w(*s1);
        c2 = locase_w(*s2);
        s1++;
        s2++;
    } while ((c1 != 0) && (c1 == c2));

    return (int)(c1 - c2);
}
