package com.example.data.user

import org.bson.codecs.pojo.annotations.BsonId
import org.bson.types.ObjectId


data class User(
    @BsonId val id:ObjectId = ObjectId(),
    val userName: String,
    val password:String,
    val salt:String
)
