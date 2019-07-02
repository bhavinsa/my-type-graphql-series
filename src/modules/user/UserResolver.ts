import {
  Resolver,
  Query,
  Mutation,
  Arg,
  UseMiddleware,
  Ctx
} from "type-graphql";
import bcrypt from "bcryptjs";
import { MyContext } from "../../types/MyContext";

import { User } from "../../entity/User";
import { RegisterInput } from "./input/RegisterInput";
import { isAuth } from "../../middleware/isAuth";
import { logger } from "../../middleware/logger";
import { sendEmail } from "../utils/sendEmail";
import { createConfirmationUrl } from "../utils/createConfirmationUrl";

import { redis } from "../../redis";
import {
  confirmUserPrefix,
  forgotPasswordPrefix
} from "../../constants/redisPrefixes";
import { v4 } from "uuid";
import { ChangePasswordInput } from "./input/ChangePasswordInput";

import { GraphQLUpload } from "graphql-upload";
import { createWriteStream } from "fs";

import { Upload } from "../../types/Upload";

@Resolver()
export class UserResolver {
  @UseMiddleware(isAuth, logger)
  @Query(() => String)
  async hello() {
    return "Hello World!";
  }

  @Mutation(() => User)
  async register(@Arg("data")
  {
    email,
    firstName,
    lastName,
    password
  }: RegisterInput): Promise<User> {
    const hashedPassword = await bcrypt.hash(password, 12);

    const user = await User.create({
      firstName,
      lastName,
      email,
      password: hashedPassword
    }).save();

    await sendEmail(email, await createConfirmationUrl(user.id));

    return user;
  }
  @Mutation(() => Boolean)
  async confirmUser(@Arg("token") token: string): Promise<boolean> {
    const userId = await redis.get(confirmUserPrefix + token);

    if (!userId) {
      return false;
    }

    await User.update({ id: parseInt(userId, 10) }, { confirmed: true });
    await redis.del(token);

    return true;
  }

  @Mutation(() => User, { nullable: true })
  async login(
    @Arg("email") email: string,
    @Arg("password") password: string,
    @Ctx() ctx: MyContext
  ): Promise<User | null> {
    const user = await User.findOne({ where: { email } });

    if (!user) {
      return null;
    }

    const valid = await bcrypt.compare(password, user.password);

    if (!valid) {
      return null;
    }

    if (!user.confirmed) {
      return null;
    }

    ctx.req.session!.userId = user.id;

    return user;
  }

  @Query(() => User, { nullable: true, complexity: 5 })
  async getUser(@Ctx() ctx: MyContext): Promise<User | undefined> {
    if (!ctx.req.session!.userId) {
      return undefined;
    }

    return User.findOne(ctx.req.session!.userId);
  }

  @Mutation(() => Boolean)
  async logout(@Ctx() ctx: MyContext): Promise<Boolean> {
    return new Promise((res, rej) =>
      ctx.req.session!.destroy(err => {
        if (err) {
          console.log(err);
          return rej(false);
        }

        ctx.res.clearCookie("qid");
        return res(true);
      })
    );
  }

  @Mutation(() => Boolean)
  async forgotPassword(@Arg("email") email: string): Promise<boolean> {
    const user = await User.findOne({ where: { email } });

    if (!user) {
      return true;
    }
    const token = v4();
    await redis.set(forgotPasswordPrefix + token, user.id, "ex", 60 * 60 * 24); // 1 day expiration
    await sendEmail(
      email,
      `http://localhost:3000/user/change-password/${token}`
    );
    return true;
  }

  @Mutation(() => User, { nullable: true })
  async changePassword(
    @Arg("data")
    { token, password }: ChangePasswordInput,
    @Ctx() ctx: MyContext
  ): Promise<User | null> {
    const userId = await redis.get(forgotPasswordPrefix + token);

    if (!userId) {
      return null;
    }

    const user = await User.findOne(userId);

    if (!user) {
      return null;
    }

    await redis.del(forgotPasswordPrefix + token);

    user.password = await bcrypt.hash(password, 12);

    await user.save();

    ctx.req.session!.userId = user.id;

    return user;
  }

  @Mutation(() => Boolean)
  async addProfilePicture(@Arg("picture", () => GraphQLUpload)
  {
    createReadStream,
    filename
  }: Upload): Promise<boolean> {
    return new Promise(async (resolve, reject) =>
      createReadStream()
        .pipe(createWriteStream(__dirname + `/../../../images/${filename}`))
        .on("finish", () => resolve(true))
        .on("error", () => reject(false))
    );
  }
}
