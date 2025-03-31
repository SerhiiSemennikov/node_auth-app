import { ApiError } from '../exceptions/ApiError.js';
import { userService } from '../services/userService.js';
import { authController } from './authController.js';
import bcrypt from 'bcrypt';

async function getAll(req, res, next) {
  const users = await userService.getAllActive();

  res.send(users.map(userService.normalize));
}

const getOne = async (req, res) => {
  const { id } = req.params;

  const user = await userService.getById(id);

  if (!user) {
    res.sendStatus(404);

    return;
  }
  res.send(user);
};

const update = async (req, res) => {
  const { id } = req.params;
  const { name, password, newPassword, confirmPassword, email } = req.body;

  const user = await userService.getOne(id);

  if (!user) {
    res.sendStatus(404);

    return;
  }

  if (typeof name !== 'string') {
    res.sendStatus(422);

    return;
  }

  if (email || (newPassword && confirmPassword)) {
    const isPwdCorrect = await bcrypt.compare(password, user.password);

    if (!isPwdCorrect) {
      throw ApiError.badRequest('Auth failed', {
        password: 'Incorrect password',
      });
    }

    const errors = {
      password:
        authController.validatePassword(newPassword) ||
        (newPassword !== confirmPassword
          ? 'Passwords do not match'
          : undefined),
    };

    if (errors.password) {
      throw ApiError.badRequest('Bad request', errors);
    }
  }

  await userService.update({
    id,
    name,
    newPassword,
    email,
  });

  const updatedUser = await userService.getOne(id);

  res.send(updatedUser);
};

export const userController = { getAll, getOne, update };
