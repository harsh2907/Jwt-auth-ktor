package com.example.data.user


interface UserDataSource {
    suspend fun getUserByUsername(userName: String):User?
    suspend fun insertUser(user:User):Boolean
}