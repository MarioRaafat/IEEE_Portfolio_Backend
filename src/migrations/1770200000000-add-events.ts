import { MigrationInterface, QueryRunner } from 'typeorm';

export class AddEvents1770200000000 implements MigrationInterface {
  name = 'AddEvents1770200000000';

  public async up(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(
      `CREATE TABLE "events" (
        "id" uuid NOT NULL DEFAULT gen_random_uuid(),
        "title" character varying NOT NULL,
        "description" text NOT NULL,
        "location" character varying NOT NULL,
        "start_time" TIMESTAMP NOT NULL,
        "end_time" TIMESTAMP NOT NULL,
        "capacity" integer NOT NULL,
        "registration_deadline" TIMESTAMP NOT NULL,
        "created_by" uuid NOT NULL,
        "created_at" TIMESTAMP NOT NULL DEFAULT now(),
        "updated_at" TIMESTAMP NOT NULL DEFAULT now(),
        CONSTRAINT "PK_events_id" PRIMARY KEY ("id")
      )`,
    );

    await queryRunner.query(
      `CREATE TYPE "public"."event_registrations_status_enum" AS ENUM('registered', 'cancelled', 'attended', 'waitlisted')`,
    );

    await queryRunner.query(
      `CREATE TABLE "event_registrations" (
        "id" uuid NOT NULL DEFAULT gen_random_uuid(),
        "user_id" uuid NOT NULL,
        "event_id" uuid NOT NULL,
        "status" "public"."event_registrations_status_enum" NOT NULL DEFAULT 'registered',
        "created_at" TIMESTAMP NOT NULL DEFAULT now(),
        "updated_at" TIMESTAMP NOT NULL DEFAULT now(),
        CONSTRAINT "PK_event_registrations_id" PRIMARY KEY ("id"),
        CONSTRAINT "UQ_event_registration_unique" UNIQUE ("event_id", "user_id")
      )`,
    );

    await queryRunner.query(
      `ALTER TABLE "events" ADD CONSTRAINT "FK_events_created_by" FOREIGN KEY ("created_by") REFERENCES "users"("id") ON DELETE RESTRICT ON UPDATE CASCADE`,
    );

    await queryRunner.query(
      `ALTER TABLE "event_registrations" ADD CONSTRAINT "FK_event_registrations_user" FOREIGN KEY ("user_id") REFERENCES "users"("id") ON DELETE CASCADE ON UPDATE CASCADE`,
    );

    await queryRunner.query(
      `ALTER TABLE "event_registrations" ADD CONSTRAINT "FK_event_registrations_event" FOREIGN KEY ("event_id") REFERENCES "events"("id") ON DELETE CASCADE ON UPDATE CASCADE`,
    );
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(
      `ALTER TABLE "event_registrations" DROP CONSTRAINT "FK_event_registrations_event"`,
    );
    await queryRunner.query(
      `ALTER TABLE "event_registrations" DROP CONSTRAINT "FK_event_registrations_user"`,
    );
    await queryRunner.query(
      `ALTER TABLE "events" DROP CONSTRAINT "FK_events_created_by"`,
    );
    await queryRunner.query(`DROP TABLE "event_registrations"`);
    await queryRunner.query(
      `DROP TYPE "public"."event_registrations_status_enum"`,
    );
    await queryRunner.query(`DROP TABLE "events"`);
  }
}
