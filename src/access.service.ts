import { Injectable, NotFoundException, UnauthorizedException } from '@nestjs/common';
import { Ability, AnyAbility, ForbiddenError, subject } from '@casl/ability';
import { AnyObject, Subject } from '@casl/ability/dist/types/types';
import { flatten } from 'flat';

import { AuthorizableRequest } from './interfaces/request.interface';
import { AbilityFactory } from './factories/ability.factory';
import { AbilityMetadata } from './interfaces/ability-metadata.interface';
import { UserProxy } from './proxies/user.proxy';
import { CaslConfig } from './casl.config';
import { AuthorizableUser } from './interfaces/authorizable-user.interface';
import { RequestProxy } from './proxies/request.proxy';
import { ConditionsProxy } from './proxies/conditions.proxy';

@Injectable()
export class AccessService {
  constructor(private abilityFactory: AbilityFactory) {
  }

  public getAbility<User extends AuthorizableUser<string, unknown> = AuthorizableUser>(user: User): AnyAbility {
    return this.abilityFactory.createForUser(user);
  }

  public hasAbility<User extends AuthorizableUser<string, unknown> = AuthorizableUser>(
    user: User,
    action: string,
    subject: Subject,
    field?: string,
    useForbiddenError = false,
  ): boolean {
    // No user - no access
    if (!user) {
      return false;
    }

    // User exists but no ability metadata - deny access
    if (!action || !subject) {
      return false;
    }

    const { superuserRole } = CaslConfig.getRootOptions();
    const userAbilities = this.abilityFactory.createForUser(user);

    // Always allow access for superuser
    if (superuserRole && user.roles?.includes(superuserRole)) {
      return true;
    }

    if (useForbiddenError)
      ForbiddenError.from(userAbilities).throwUnlessCan(action, subject, field);

    return userAbilities.can(action, subject, field);
  }

  public assertAbility<User extends AuthorizableUser<string, unknown> = AuthorizableUser>(
    user: User,
    action: string,
    subject: Subject,
    field?: string,
  ): void {
    if (!this.hasAbility(user, action, subject, field)) {
      const userAbilities = this.abilityFactory.createForUser(user, Ability);
      const relatedRules = userAbilities.rulesFor(action, typeof subject === 'object' ? subject.constructor : subject);
      if (relatedRules.some((rule) => rule.conditions)) {
        throw new NotFoundException();
      }
      throw new UnauthorizedException();
    }
  }

  public async canActivateAbility<Subject = AnyObject>(
    request: AuthorizableRequest,
    ability?: AbilityMetadata<Subject>,
    useForbiddenError = true,
  ): Promise<{ can: boolean, errors?: string[] }> {
    const { getUserFromRequest, superuserRole } = CaslConfig.getRootOptions();

    const userProxy = new UserProxy(request, getUserFromRequest);
    const req = new RequestProxy(request);

    // Attempt to get user from request
    const user = userProxy.getFromRequest();

    // No user - no access
    if (!user)
      return { can: false };

    // User exists but no ability metadata - deny access
    if (!ability)
      return { can: false };

    // Always allow access for superuser
    if (superuserRole && user.roles?.includes(superuserRole))
      return { can: true };

    let userAbilities = this.abilityFactory.createForUser(user, Ability);
    const relevantRules = userAbilities.rulesFor(ability.action, ability.subject);

    req.setConditions(new ConditionsProxy(userAbilities, ability.action, ability.subject));

    // If no relevant rules with conditions or no subject hook exists check against subject class
    if (!relevantRules.every((rule) => rule.conditions) || !ability.subjectHook)
      return { can: userAbilities.can(ability.action, ability.subject) };

    // Otherwise try to obtain subject
    const subjectInstance = await req.getSubjectHook().run(request);
    req.setSubject(subjectInstance);

    if (!subjectInstance)
      return { can: userAbilities.can(ability.action, ability.subject) };

    const finalUser = await userProxy.get();
    if (finalUser && finalUser !== userProxy.getFromRequest())
      userAbilities = this.abilityFactory.createForUser(finalUser);

    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const actualSubject = subject(ability.subject as any, subjectInstance);

    const { cant, errors } = this.isThereAnyFieldRestriction(
      request.body,
      ability.action,
      actualSubject,
      finalUser,
      useForbiddenError,
    );
    if (cant) return { can: cant, errors };

    // and match agains subject instance=
    if (useForbiddenError)
      ForbiddenError.from(userAbilities).throwUnlessCan(ability.action, actualSubject);
    return { can: userAbilities.can(ability.action, actualSubject) };
  }

  private isThereAnyFieldRestriction(
    body: Record<string, string>,
    action: string,
    subject: AnyObject,
    user?: AuthorizableUser<string, string>,
    useForbiddenError = false,
  ): { cant: boolean; errors?: string[] } {
    if (!user) return { cant: true };

    const subjectFields = Object.keys(flatten(body || {}));

    if (useForbiddenError) {
      const errors = [];
      let failed = false;
      for (const field of subjectFields) {
        try {
          ForbiddenError.from(this.getAbility(user)).throwUnlessCan(action, subject, field);
        } catch (error) {
          failed = true;
          if (error instanceof ForbiddenError)
            errors.push(error.message);
        }
      }
      return { cant: failed, errors };
    }

    return { cant: subjectFields.some((field) => !this.hasAbility(user, action, subject, field)) };
  }
}
