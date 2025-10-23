import { NextResponse } from 'next/server';
import type { NextRequest } from 'next/server';

export interface MiddlewareConfig {
  protectedPaths: string[];
  publicPaths?: string[];
  loginPath?: string;
}

export function createAuthMiddleware(config: MiddlewareConfig) {
  const {
    protectedPaths,
    publicPaths = ['/login', '/register'],
    loginPath = '/login',
  } = config;

  return async function middleware(request: NextRequest) {
    const { pathname } = request.nextUrl;

    // Check if path is public
    if (publicPaths.some(path => pathname.startsWith(path))) {
      return NextResponse.next();
    }

    // Check if path is protected
    const isProtected = protectedPaths.some(path => pathname.startsWith(path));

    if (isProtected) {
      const token = request.cookies.get('accessToken')?.value || 
                    request.headers.get('authorization')?.split(' ')[1];

      if (!token) {
        return NextResponse.redirect(new URL(loginPath, request.url));
      }

      try {
        // Verify token (simplified for edge runtime)
        const payload = JSON.parse(
          Buffer.from(token.split('.')[1], 'base64').toString()
        );

        // Check expiration
        if (payload.exp && Date.now() >= payload.exp * 1000) {
          return NextResponse.redirect(new URL(loginPath, request.url));
        }

        return NextResponse.next();
      } catch {
        return NextResponse.redirect(new URL(loginPath, request.url));
      }
    }

    return NextResponse.next();
  };
}

export const config = {
  matcher: ['/((?!api|_next/static|_next/image|favicon.ico).*)'],
};
