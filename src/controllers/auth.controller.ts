import { Request, Response, NextFunction } from "express";
import jwt from "jsonwebtoken";
import { prisma } from "../utils/prisma";
import { CreateUserInput, LoginUserInput } from "../schema/user.schema";
import {
  getGoogleOauthToken,
  getGoogleUser,
  getGithubOathToken,
  getGithubUser,
} from "../services/session.service";

/* Utils */
const TOKEN_EXPIRES_IN = Number(process.env.TOKEN_EXPIRES_IN);
const TOKEN_SECRET = process.env.JWT_SECRET as string;
const FRONTEND_ORIGIN = process.env.FRONTEND_ORIGIN as string;

const signAndSetCookie = (res: Response, userId: string) => {
  const token = jwt.sign({ sub: userId }, TOKEN_SECRET, {
    expiresIn: `${TOKEN_EXPIRES_IN}m`,
  });

  res.cookie("token", token, {
    expires: new Date(Date.now() + TOKEN_EXPIRES_IN * 60 * 1000),
  });
};

export const exclude = <T, K extends keyof T>(obj: T, keys: K[]) => {
  keys.forEach((k) => delete obj[k]);
  return obj;
};

/* Auth */
export const registerHandler = async (
  req: Request<{}, {}, CreateUserInput>,
  res: Response,
  next: NextFunction
) => {
  try {
    const user = await prisma.user.create({
      data: { ...req.body, createdAt: new Date() },
    });

    res.status(201).json({
      status: "success",
      data: { user: exclude(user, ["password"]) },
    });
  } catch (err: any) {
    if (err.code === "P2002") {
      return res.status(409).json({
        status: "fail",
        message: "Email already exist",
      });
    }
    next(err);
  }
};

export const loginHandler = async (
  req: Request<{}, {}, LoginUserInput>,
  res: Response,
  next: NextFunction
) => {
  try {
    const user = await prisma.user.findUnique({
      where: { email: req.body.email },
    });

    if (!user || user.provider !== "Credentials") {
      return res.status(401).json({
        status: "fail",
        message: user
          ? `Use ${user.provider} OAuth2 instead`
          : "Invalid email or password",
      });
    }

    signAndSetCookie(res, user.id);
    res.status(200).json({ status: "success" });
  } catch (err) {
    next(err);
  }
};

export const logoutHandler = (_: Request, res: Response) => {
  res.cookie("token", "", { maxAge: -1 });
  res.status(200).json({ status: "success" });
};

/* OAuth */
const oauthLogin = async (
  res: Response,
  pathUrl: string,
  userData: {
    email: string;
    name: string;
    photo?: string;
    provider: "Google" | "GitHub";
  }
) => {
  const user = await prisma.user.upsert({
    where: { email: userData.email },
    create: {
      ...userData,
      password: "",
      verified: true,
      createdAt: new Date(),
    },
    update: userData,
  });

  signAndSetCookie(res, user.id);
  res.redirect(`${FRONTEND_ORIGIN}${pathUrl}`);
};

export const googleOauthHandler = async (req: Request, res: Response) => {
  try {
    const code = req.query.code as string;
    const pathUrl = (req.query.state as string) || "/";

    if (!code) throw new Error("Missing code");

    const { id_token, access_token } = await getGoogleOauthToken({ code });
    const { email, name, picture, verified_email } =
      await getGoogleUser({ id_token, access_token });

    if (!verified_email) {
      return res.status(403).json({
        status: "fail",
        message: "Google account not verified",
      });
    }

    await oauthLogin(res, pathUrl, {
      email,
      name,
      photo: picture,
      provider: "Google",
    });
  } catch {
    res.redirect(`${FRONTEND_ORIGIN}/oauth/error`);
  }
};

export const githubOauthHandler = async (req: Request, res: Response) => {
  try {
    if (req.query.error) {
      return res.redirect(`${FRONTEND_ORIGIN}/login`);
    }

    const code = req.query.code as string;
    const pathUrl = (req.query.state as string) || "/";

    if (!code) throw new Error("Missing code");

    const { access_token } = await getGithubOathToken({ code });
    const { email, login, avatar_url } = await getGithubUser({ access_token });

    await oauthLogin(res, pathUrl, {
      email,
      name: login,
      photo: avatar_url,
      provider: "GitHub",
    });
  } catch {
    res.redirect(`${FRONTEND_ORIGIN}/oauth/error`);
  }
};
