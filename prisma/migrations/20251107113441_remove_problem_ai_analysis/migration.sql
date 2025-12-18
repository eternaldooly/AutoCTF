/*
  Warnings:

  - You are about to drop the column `ai_analysis` on the `Problem` table. All the data in the column will be lost.
  - You are about to drop the column `ai_analysis_generated_at` on the `Problem` table. All the data in the column will be lost.

*/
-- RedefineTables
PRAGMA defer_foreign_keys=ON;
PRAGMA foreign_keys=OFF;
CREATE TABLE "new_Problem" (
    "id" TEXT NOT NULL PRIMARY KEY,
    "title" TEXT NOT NULL,
    "description" TEXT NOT NULL,
    "category" TEXT NOT NULL,
    "difficulty" TEXT NOT NULL,
    "points" INTEGER NOT NULL DEFAULT 0,
    "hints" TEXT,
    "files" TEXT,
    "solved" BOOLEAN NOT NULL DEFAULT false,
    "source" TEXT,
    "createdAt" DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" DATETIME NOT NULL,
    "competitionId" TEXT NOT NULL,
    CONSTRAINT "Problem_competitionId_fkey" FOREIGN KEY ("competitionId") REFERENCES "Competition" ("id") ON DELETE CASCADE ON UPDATE CASCADE
);
INSERT INTO "new_Problem" ("category", "competitionId", "createdAt", "description", "difficulty", "files", "hints", "id", "points", "solved", "source", "title", "updatedAt") SELECT "category", "competitionId", "createdAt", "description", "difficulty", "files", "hints", "id", "points", "solved", "source", "title", "updatedAt" FROM "Problem";
DROP TABLE "Problem";
ALTER TABLE "new_Problem" RENAME TO "Problem";
PRAGMA foreign_keys=ON;
PRAGMA defer_foreign_keys=OFF;
