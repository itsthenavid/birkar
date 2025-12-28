-- DropIndex
DROP INDEX "AuthToken_userId_purpose_idx";

-- CreateIndex
CREATE INDEX "AuthToken_userId_purpose_createdAt_idx" ON "AuthToken"("userId", "purpose", "createdAt");
