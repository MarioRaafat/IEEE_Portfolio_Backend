import { MigrationInterface, QueryRunner } from 'typeorm';

export class SeedRoles1764886100000 implements MigrationInterface {
  name = 'SeedRoles1764886100000';

  public async up(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(`
      INSERT INTO "roles" ("name", "description") VALUES
        ('Super Admin', 'Super admin role'),
        ('Admin', 'Admin role'),
        ('Faculty Member', 'Faculty member role'),
        ('Visitor', 'Visitor role')
      ON CONFLICT ("name") DO NOTHING
    `);
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    await queryRunner.query(`
      DELETE FROM "roles" WHERE "name" IN ('Super Admin', 'Admin', 'Faculty Member', 'Visitor')
    `);
  }
}
