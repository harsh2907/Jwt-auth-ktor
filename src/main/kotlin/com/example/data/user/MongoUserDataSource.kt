package com.example.data.user

import org.litote.kmongo.coroutine.CoroutineDatabase
import org.litote.kmongo.eq


class MongoUserDataSource(
   private val db:CoroutineDatabase
):UserDataSource {

    private val users = db.getCollection<User>()

    override suspend fun getUserByUsername(userName: String): User? {
        return users.findOne(User::userName eq userName)
    }

    override suspend fun insertUser(user: User): Boolean {
        return users.insertOne(user).wasAcknowledged()
    }
}