import type { JwkSet } from '@openid4vc/oauth2'
import type { Response, Router } from 'express'
import { getRequestContext, sendJsonResponse, sendUnknownServerErrorResponse } from '../../shared/router'
import type { OpenId4VcIssuerModuleConfig } from '../OpenId4VcIssuerModuleConfig'
import type { OpenId4VcIssuanceRequest } from './requestContext'

export function configureJwksEndpoint(router: Router, config: OpenId4VcIssuerModuleConfig) {
  router.get(config.jwksEndpointPath, async (_request: OpenId4VcIssuanceRequest, response: Response, next) => {
    const { agentContext, issuer } = getRequestContext(_request)
    try {
      const keys = [issuer.resolvedAccessTokenPublicJwk, ...issuer.resolvedJwks]
      const jwks: JwkSet = {
        keys: keys.map((key) => key.toJson({ includeKid: true })),
      }
      return sendJsonResponse(response, next, jwks, 'application/jwk-set+json')
    } catch (e) {
      return sendUnknownServerErrorResponse(response, next, agentContext.config.logger, e)
    }
  })
}
