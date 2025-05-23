typedef unsigned char des_user_key[8];
typedef unsigned char des_cblock[8];
typedef unsigned long des_ks[32];

void _des_crypt( des_cblock in, des_cblock out, des_ks key, int encrypt );
void _des_expand_key( des_user_key userKey, des_ks key );

void perl_des_crypt( des_cblock input, des_cblock output, des_ks ks, int encrypt );
void perl_des_expand_key(des_user_key userKey, des_ks ks);
