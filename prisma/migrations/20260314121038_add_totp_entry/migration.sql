-- CreateTable
CREATE TABLE "TotpEntry" (
    "id" TEXT NOT NULL,
    "userId" TEXT NOT NULL,
    "issuer" TEXT NOT NULL,
    "accountName" TEXT NOT NULL,
    "encryptedSecret" BYTEA NOT NULL,
    "iv" BYTEA NOT NULL,
    "authTag" BYTEA NOT NULL,
    "encryptedDek" BYTEA NOT NULL,
    "dekIv" BYTEA NOT NULL,
    "dekAuthTag" BYTEA NOT NULL,
    "algorithm" TEXT NOT NULL DEFAULT 'SHA1',
    "digits" INTEGER NOT NULL DEFAULT 6,
    "period" INTEGER NOT NULL DEFAULT 30,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "TotpEntry_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE INDEX "TotpEntry_userId_idx" ON "TotpEntry"("userId");

-- AddForeignKey
ALTER TABLE "TotpEntry" ADD CONSTRAINT "TotpEntry_userId_fkey" FOREIGN KEY ("userId") REFERENCES "User"("id") ON DELETE CASCADE ON UPDATE CASCADE;
