-- CreateTable
CREATE TABLE "best_practice_rule_definitions" (
    "id" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "owner" TEXT NOT NULL,
    "description" TEXT NOT NULL,
    "how_to_check" TEXT NOT NULL,
    "how_to_exempt" TEXT NOT NULL
);

-- CreateIndex
CREATE UNIQUE INDEX "best_practice_rule_definitions_id_key" ON "best_practice_rule_definitions"("id");
