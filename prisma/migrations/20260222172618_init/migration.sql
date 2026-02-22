/*
  Warnings:

  - You are about to drop the column `tokenId` on the `Session` table. All the data in the column will be lost.

*/
-- DropIndex
DROP INDEX "Session_tokenId_key";

-- AlterTable
ALTER TABLE "Session" DROP COLUMN "tokenId";
