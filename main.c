#include "main.h"

int main(int args, char *argv[])
{
    bzrtpContext_t * context = bzrtp_createBzrtpContext();

    int SSRC = 0;

    int ok = bzrtp_initBzrtpContext(context, SSRC);

    if (!ok)
    {
        printf("%d\n", context->isInitialised);
        contact_t * contact1 = initContact();
        if (contact1)
        {
            contact1->supportedHash[0] = 0;
        }

        destroyContact(contact1);
    }
    bzrtp_destroyBzrtpContext(context, 0);

    return 0;
}