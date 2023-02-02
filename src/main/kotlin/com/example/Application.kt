package com.example

import com.example.data.user.MongoUserDataSource
import io.ktor.server.application.*
import com.example.plugins.*
import com.example.security.hashing.SHA256HashingService
import com.example.security.token.JwtTokenService
import com.example.security.token.TokenConfig
import com.mongodb.MongoClientSettings
import com.mongodb.MongoDriverInformation
import com.mongodb.reactivestreams.client.MongoClients
import org.litote.kmongo.coroutine.coroutine
import org.litote.kmongo.reactivestreams.KMongo
import java.util.concurrent.TimeUnit

fun main(args: Array<String>): Unit =
    io.ktor.server.netty.EngineMain.main(args)

@Suppress("unused")
fun Application.module() {

    val mongoUsername = System.getenv("MONGO_USER")
    val mongoPass = System.getenv("MONGO_PW")
    val dbString = "mongodb+srv://$mongoUsername:$mongoPass@cluster0.y8sigc0.mongodb.net/?retryWrites=true&w=majority"


    val db = KMongo.createClient(
        connectionString = dbString,
    ).coroutine.getDatabase("ktor-auth")

    println(db.name)
    val userDataSource = MongoUserDataSource(db)
    val tokenService = JwtTokenService()
    val tokenConfig = TokenConfig(
        issuer = environment.config.property("jwt.issuer").getString(),
        audience = environment.config.property("jwt.audience").getString(),
        expiresIn = 365L * 24L * 60L * 60L * 1000L,
        secret = System.getenv("JWT_SECRET")
    )
    val hashingService = SHA256HashingService()

    configureSecurity(tokenConfig)
    configureRouting(
        hashingService = hashingService,
        tokenConfig = tokenConfig,
        tokenService = tokenService,
        userDataSource = userDataSource
    )
    configureSerialization()
    configureMonitoring()

}
