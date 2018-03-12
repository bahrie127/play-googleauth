package com.gu.googleauth

import java.time.{Clock, Duration}

import io.jsonwebtoken.{ExpiredJwtException, SignatureException, UnsupportedJwtException}
import io.jsonwebtoken.SignatureAlgorithm.{HS256, HS384}
import org.scalatest.{FlatSpec, Matchers, TryValues}
import play.api.mvc.RequestHeader
import play.api.test.FakeRequest

class AntiForgeryCheckerTest extends FlatSpec with Matchers with TryValues {

  val ExampleSessionId = OAuthStateSecurityConfig.generateSessionId()

  val antiForgery = OAuthStateSecurityConfig("reallySecret", HS256)

  "Anti Forgery" should "fail if token is signed with other algorithm, even if it has the same secret" in {
    val badAlgorithmAntiForgery = antiForgery.copy(signatureAlgorithm = HS384)

      antiForgery.extractOAuthStateFrom(mockRequest(badAlgorithmAntiForgery.generateToken(ExampleSessionId), ExampleSessionId))
        .failure.exception should have message "the anti forgery token is not signed with HS256"
  }

  it should "fail if the Play session id is different to the token id" in {
    val otherSessionId = OAuthStateSecurityConfig.generateSessionId()
    val badSessionAntiForgery = antiForgery.generateToken(otherSessionId)

    antiForgery.extractOAuthStateFrom(mockRequest(badSessionAntiForgery, ExampleSessionId))
      .failure.exception should have message "the session ID found in the anti forgery token does not match the Play session ID"
  }

  it should "not allow the 'None' algorithm" in {
    val tokenSignedWithNoneAlgorithm = "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJuYmYiOjE1MTUxNTE3ODUsImV4cCI6MjA1MTYwOTI5MDAwMH0."

    antiForgery.extractOAuthStateFrom(mockRequest(tokenSignedWithNoneAlgorithm, ExampleSessionId))
      .failure.exception shouldBe a [UnsupportedJwtException]
  }

  it should "not accept an expired token" in {
    val clockOneHourBehindCurrentTime = Clock.offset(Clock.systemUTC(), Duration.ofHours(1).negated())
    val expiredToken = antiForgery.generateToken(ExampleSessionId)(clockOneHourBehindCurrentTime)

    antiForgery.extractOAuthStateFrom(mockRequest(expiredToken, ExampleSessionId))
      .failure.exception shouldBe a [ExpiredJwtException]
  }

  it should "accept a valid token" in {
    val validToken = antiForgery.generateToken(ExampleSessionId)

    antiForgery.extractOAuthStateFrom(mockRequest(validToken, ExampleSessionId)).isSuccess shouldBe true
  }

  it should "not accept a token missing a character" in {
    val tokenMissingCharacter = antiForgery.generateToken(ExampleSessionId).dropRight(1)

      antiForgery.extractOAuthStateFrom(mockRequest(tokenMissingCharacter, ExampleSessionId))
      .failure.exception shouldBe a [SignatureException]
  }

  def mockRequest(state: String, sessionId: String): RequestHeader = {
    FakeRequest("GET", path = s"?state=$state").withSession(antiForgery.sessionIdKeyName -> sessionId)
  }

}
