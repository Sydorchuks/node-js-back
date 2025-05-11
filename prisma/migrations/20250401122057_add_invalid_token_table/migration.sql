-- CreateTable
CREATE TABLE "InvalidToken" (
    "id" TEXT NOT NULL,
    "token" TEXT NOT NULL,
    "userId" TEXT NOT NULL,
    "expiresAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "InvalidToken_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX "InvalidToken_token_key" ON "InvalidToken"("token");

-- AddForeignKey
ALTER TABLE "InvalidToken" ADD CONSTRAINT "InvalidToken_userId_fkey" FOREIGN KEY ("userId") REFERENCES "users"("id") ON DELETE CASCADE ON UPDATE CASCADE;
