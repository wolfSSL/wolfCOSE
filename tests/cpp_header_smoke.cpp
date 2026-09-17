#include <wolfcose/eat_psa.h>
#include <wolfcose/version.h>
#include <wolfcose/wolfcose.h>

int main()
{
    WOLFCOSE_KEY key;

    wc_CoseKey_Init(&key);
    return (LIBWOLFCOSE_VERSION_HEX == 0u) ? 1 : 0;
}
