import bcrypt from 'bcrypt';
import { v4 as uuidv4 } from 'uuid';

import { emailService } from '../services/emailService.js';
import { ApiError } from '../exceptions/ApiError.js';
import { User } from '../models/User.js';

function getAllActive() {
  return User.findAll({
    where: { activationToken: null },
    order: ['id'],
  });
}

async function getOne(id) {
  return User.findOne({ where: id });
}

function getByEmail(email) {
  return User.findOne({
    where: { email },
  });
}

function normalize({ id, email }) {
  return { id, email };
}

async function register({ email, password }) {
  const existingUser = await getByEmail(email);

  if (existingUser) {
    throw ApiError.BadRequest('Validation error', {
      email: 'Email is already taken',
    });
  }

  const activationToken = uuidv4();
  const hash = await bcrypt.hash(password, 10);

  await User.create({
    email,
    password: hash,
    activationToken,
  });

  await emailService.sendActivationLink(email, activationToken);
}

async function update(
  id,
  name = undefined,
  password = undefined,
  email = undefined,
) {
  const user = await User.findOne({ where: { id } });

  if (name) {
    user.name = name;
  }

  if (password) {
    const hashedPass = await bcrypt.hash(password, 10);

    user.password = hashedPass;
  }

  if (email) {
    user.email = email;
  }

  if (user) {
    try {
      await User.update({ name, password, email }, { where: { id } });
    } catch (error) {
      // eslint-disable-next-line no-console
      console.log(`Error updating user by id ${id}`, error);
      throw error;
    }
  }
  await user.save();
}

async function reqPasswordReset(email) {
  const passwordResetToken = uuidv4();
  const user = await getByEmail(email);

  user.passwordResetToken = passwordResetToken;
  await user.save();
  emailService.sendResetEmail(email, passwordResetToken);
}

export const userService = {
  getAllActive,
  normalize,
  getByEmail,
  register,
  getOne,
  update,
  reqPasswordReset,
};

// uuidv4();
