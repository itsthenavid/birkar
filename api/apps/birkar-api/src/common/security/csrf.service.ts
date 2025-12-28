import { Injectable } from '@nestjs/common';
import { randomToken } from '../utils/crypto';

@Injectable()
export class CsrfService {
  issueToken(): string {
    return randomToken(24);
  }
}
