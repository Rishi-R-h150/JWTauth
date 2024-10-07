import passport from "passport"
import Strategy from "passport-local"
import { comparePassword } from "../hashPassword.mjs"
import { User } from "../dbSchema/userSchema.mjs"
import jwt from "jsonwebtoken"
const JWT_SECRET = "my_jwt_secret";
passport.use(
    new Strategy(async (username, password, done) => {
        try {
            console.log("Searching for user:", username);
            const user = await User.findOne({ username });
            if (!user) {
                console.log("User not found");
                return done(null, false, { message: "User not found" });
            }

            console.log("User found:", user.username);
            if (!comparePassword(password, user.password)) {
                console.log("Password mismatch");
                return done(null, false, { message: "Incorrect password" });
            }

            console.log("Password matched, generating token");
            const token = jwt.sign({ id: user._id, role: user.role }, JWT_SECRET, {
                expiresIn: "1h"
            });
            return done(null, { user, token });

        } catch (err) {
            console.log("Error:", err);
            return done(err);
        }
    })
);
export default passport