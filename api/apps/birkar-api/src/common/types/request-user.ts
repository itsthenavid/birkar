export type RequestUser = {
  id: string;
};

export type AuthedRequest = Request & { user?: RequestUser };
