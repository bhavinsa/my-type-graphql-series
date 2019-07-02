import { buildSchema } from "type-graphql";
import { AuthorBookResolver } from "../modules/author-book/AuthorBookResolver";
import { UserResolver } from "../modules/user/UserResolver";

export const createSchema = () =>
  buildSchema({
    resolvers: [
      UserResolver,
      AuthorBookResolver
    ],
    authChecker: ({ context: { req } }) => {
      return !!req.session.userId;
    }
  });
