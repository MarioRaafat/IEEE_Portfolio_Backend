import { MigrationInterface, QueryRunner } from "typeorm";

export class PhoneNumberRequired1770042012033 implements MigrationInterface {
    name = 'PhoneNumberRequired1770042012033'

    public async up(queryRunner: QueryRunner): Promise<void> {
        await queryRunner.query(`ALTER TABLE "users" ALTER COLUMN "phone" SET NOT NULL`);
    }

    public async down(queryRunner: QueryRunner): Promise<void> {
        await queryRunner.query(`ALTER TABLE "users" ALTER COLUMN "phone" DROP NOT NULL`);
    }

}
