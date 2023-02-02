package com.example

import com.example.data.request.AuthRequest
import com.example.data.responses.AuthResponse
import com.example.data.user.User
import com.example.data.user.UserDataSource
import com.example.security.hashing.HashingService
import com.example.security.hashing.SaltedHash
import com.example.security.token.TokenClaim
import com.example.security.token.TokenConfig
import com.example.security.token.TokenService
import io.ktor.http.*
import io.ktor.server.application.*
import io.ktor.server.auth.*
import io.ktor.server.auth.jwt.*
import io.ktor.server.request.*
import io.ktor.server.response.*
import io.ktor.server.routing.*

fun Route.signUp(
    hashingService: HashingService,
    userDataSource: UserDataSource
) {
    post("signup") {
        val request = call.receiveNullable<AuthRequest>() ?: kotlin.run {
            call.respond(HttpStatusCode.BadRequest)
            return@post
        }

        val userAlreadyExist = userDataSource.getUserByUsername(request.username)!=null
        if (userAlreadyExist) {
            call.respondText(
                "User already exist with this username ${request.username}",
                status = HttpStatusCode.Conflict
            )
            return@post
        }

        val isUsernameBlank = request.username.isBlank()
        val isPasswordBlank = request.password.isBlank()
        val isPassTooShort = request.password.length < 6

        if (isUsernameBlank) {
            call.respondText(
                "Username can't be blank",
                status = HttpStatusCode.Conflict
            )
            return@post
        }
        if (isPasswordBlank || isPassTooShort) {
            call.respondText(
                "Password length must be at least 6 characters",
                status = HttpStatusCode.Conflict
            )
            return@post
        }

        val saltedHash = hashingService.generateSaltedHash(request.password)
        val user = User(
            userName = request.username,
            password = saltedHash.hash,
            salt = saltedHash.salt
        )
        val wasAcknowledged = userDataSource.insertUser(user)
        if (!wasAcknowledged) {
            call.respond(HttpStatusCode.Conflict)
            return@post
        }

        call.respond(HttpStatusCode.OK)

    }
}

fun Route.signIn(
    userDataSource: UserDataSource,
    hashingService: HashingService,
    tokenService: TokenService,
    tokenConfig: TokenConfig
) {
    post("signin") {
        val request = call.receiveNullable<AuthRequest>() ?: kotlin.run {
            call.respond(HttpStatusCode.BadRequest)
            return@post
        }

        val user = userDataSource.getUserByUsername(request.username)
        if (user == null) {
            call.respond(
                HttpStatusCode.Unauthorized,
                "Inccorect username or password"
            )
            return@post
        }

        val isValidPassword = hashingService.verify(
            value = request.password,
            saltedHash = SaltedHash(
                hash = user.password,
                salt = user.salt
            )
        )

        if(!isValidPassword){
            call.respond(
                HttpStatusCode.Unauthorized,
                "Inccorect username or password"
            )
            return@post
        }

        val token = tokenService.generate(
            config = tokenConfig,
            TokenClaim(
                name = "userId",
                value = user.id.toString()
            )
        )

        call.respond(
            status = HttpStatusCode.OK,
            message = AuthResponse(token)
        )
    }
}

//Auto login functionality
fun Route.authenticate(){
    authenticate {
        get("authenticate") {
            call.respond(HttpStatusCode.OK)
        }
    }
}

//For testing purpose only. Can be removed
fun Route.getSecretInfo(){
    authenticate{
        get("secret"){
            val principal = call.principal<JWTPrincipal>()
            val userId = principal?.getClaim("userId",String::class)
            call.respond(HttpStatusCode.OK,"Your userId is $userId")
        }
    }
}