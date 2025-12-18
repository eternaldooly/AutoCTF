-- RedefineTables
PRAGMA defer_foreign_keys=ON;
PRAGMA foreign_keys=OFF;
CREATE TABLE "new_Competition" (
    "id" TEXT NOT NULL PRIMARY KEY,
    "name" TEXT NOT NULL,
    "description" TEXT,
    "ctfUrl" TEXT,
    "databaseName" TEXT,
    "apiKey" TEXT,
    "ownerEmail" TEXT NOT NULL DEFAULT 'unowned',
    "ownerName" TEXT,
    "isShared" BOOLEAN NOT NULL DEFAULT false,
    "createdAt" DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" DATETIME NOT NULL
);
INSERT INTO "new_Competition" ("apiKey", "createdAt", "ctfUrl", "databaseName", "description", "id", "name", "ownerEmail", "ownerName", "updatedAt") SELECT "apiKey", "createdAt", "ctfUrl", "databaseName", "description", "id", "name", "ownerEmail", "ownerName", "updatedAt" FROM "Competition";
DROP TABLE "Competition";
ALTER TABLE "new_Competition" RENAME TO "Competition";
CREATE INDEX "Competition_ownerEmail_idx" ON "Competition"("ownerEmail");
PRAGMA foreign_keys=ON;
PRAGMA defer_foreign_keys=OFF;
