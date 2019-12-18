package com.westone.rpcserver;

interface IfCreateSoftCard {
    public long createSoftCard(String token, String userName, String licSesrverip, int licport1, int licport2, String csppip, int csppport1, int csppport2);
    public long Destroy_CipherCard();
}
