import { MigrationInterface, QueryRunner } from 'typeorm';

export class AddUsernameToUsers1764886000000 implements MigrationInterface {
  name = 'AddUsernameToUsers1764886000000';

  public async up(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(
      `ALTER TABLE "users" ADD "username" character varying`,
    );
    await queryRunner.query(
      `ALTER TABLE "users" ADD CONSTRAINT "UQ_users_username" UNIQUE ("username")`,
    );
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(
      `ALTER TABLE "users" DROP CONSTRAINT "UQ_users_username"`,
    );
    await queryRunner.query(`ALTER TABLE "users" DROP COLUMN "username"`);
  }
}
