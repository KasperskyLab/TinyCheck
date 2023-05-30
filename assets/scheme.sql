CREATE TABLE "iocs" (
	"id"	INTEGER UNIQUE,
	"value"	   TEXT NOT NULL,
	"type"	   TEXT NOT NULL,
	"tlp"	   TEXT NOT NULL,
	"tag"	   TEXT NOT NULL,
	"source"   TEXT NOT NULL,
	"added_on" TEXT NOT NULL,
	PRIMARY KEY("id" AUTOINCREMENT)
);

CREATE TABLE "whitelist" (
	"id"	INTEGER UNIQUE,
	"element"  TEXT NOT NULL UNIQUE,
	"type"	   TEXT NOT NULL,
	"source"   TEXT NOT NULL,
	"added_on" TEXT NOT NULL,
	PRIMARY KEY("id" AUTOINCREMENT)
);

CREATE TABLE "misp" (
	"id" 	 INTEGER UNIQUE,
	"name" 	     TEXT,
	"url"	     TEXT NOT NULL,
	"apikey"     TEXT NOT NULL,
	"verifycert" INTEGER NOT NULL DEFAULT 0,
	"added_on"   TEXT NOT NULL,
	"last_sync"  TEXT NOT NULL DEFAULT 0,
	PRIMARY KEY("id" AUTOINCREMENT)
);
