import com.typesafe.config.ConfigFactory
import io.ktor.client.request.*
import io.ktor.client.statement.*
import io.ktor.server.config.*
import io.ktor.http.*
import io.ktor.server.testing.*
import kotlinx.serialization.Serializable
import kotlinx.serialization.decodeFromString
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import org.hyperskill.hstest.dynamic.DynamicTest
import org.hyperskill.hstest.stage.StageTest
import org.hyperskill.hstest.testcase.CheckResult

class HotKitchenTest : StageTest<Any>() {

    @Serializable
    private data class Credentials(var email: String, var userType: String, var password: String)

    @Serializable
    private data class User(
        val name: String, val userType: String, val phone: String, val email: String, val address: String
    )

    private fun User.isEquals(user: User) =
        name == user.name && userType == user.userType && phone == user.phone && email == user.email && address == user.address


    @Serializable
    private data class Token(val token: String)

    private val time = System.currentTimeMillis().toString()
    private val jwtRegex = """^[a-zA-Z0-9]+?\.[a-zA-Z0-9]+?\..+""".toRegex()
    private val currentCredentials = Credentials("$time@mail.com", "client", "password$time")
    private var currentUser = User(time + "name", "client", "+79999999999", currentCredentials.email, time + "address")
    private lateinit var signInToken: String


    @DynamicTest(order = 1)
    fun getSignInJWTToken(): CheckResult {
        var result = CheckResult.correct()
        try {
            testApplication {
                val response = client.post("/signup") {
                    setBody(Json.encodeToString(currentCredentials))
                    header(HttpHeaders.ContentType, ContentType.Application.Json.toString())
                }
                try {
                    val principal = Json.decodeFromString<Token>(response.bodyAsText() ?: "")
                    signInToken = principal.token
                    if (!signInToken.matches(jwtRegex) || signInToken.contains(currentCredentials.email))
                        result = CheckResult.wrong("Invalid JWT token")
                } catch (e: Exception) {
                    result = CheckResult.wrong("Cannot get token form /signup request")
                }
            }
        } catch (e: Exception) {
            result = CheckResult.wrong(e.message)
        }
        return result
    }

    @DynamicTest(order = 2)
    fun correctValidation(): CheckResult {
        var result = CheckResult.correct()
        try {
            testApplication {
                val response = client.get("/validate") {
                    header(HttpHeaders.Authorization, "Bearer $signInToken")
                }
                if (response.status != HttpStatusCode.OK
                    || response.bodyAsText() != "Hello, ${currentCredentials.userType} ${currentCredentials.email}")
                    result = CheckResult.wrong("Token validation with signin token failed.\n" +
                            "Status code should be \"200 OK\"\n" +
                            "Message should be \"Hello, ${currentCredentials.userType} ${currentCredentials.email}\"")
            }
        } catch (e: Exception) {
            result = CheckResult.wrong(e.message)
        }
        return result
    }

    @DynamicTest(order = 3)
    fun getNonExistentUser(): CheckResult {
        var result = CheckResult.correct()
        try {
            testApplication {
                val response = client.get("/me") {
                    header(HttpHeaders.Authorization, "Bearer $signInToken")
                }
                if (response.status != HttpStatusCode.BadRequest)
                    result = CheckResult.wrong("Status code for a getting non-existent user should be \"400 Bad Request\"")
            }
        } catch (e: Exception) {
            result = CheckResult.wrong(e.message)
        }
        return result
    }

    @DynamicTest(order = 4)
    fun createUser(): CheckResult {
        var result = CheckResult.correct()
        try {
            testApplication {
                val response = client.put("/me") {
                    setBody(Json.encodeToString(currentUser))
                    header(HttpHeaders.ContentType, ContentType.Application.Json.toString())
                    header(HttpHeaders.Authorization, "Bearer $signInToken")
                }
                if (response.status != HttpStatusCode.OK)
                    result = CheckResult.wrong("Cannot add user by put method")
            }
        } catch (e: Exception) {
            result = CheckResult.wrong(e.message)
        }
        return result
    }

    @DynamicTest(order = 5)
    fun getExistentUser(): CheckResult {
        var result = CheckResult.correct()
        try {
            testApplication {
                val response = client.get("/me") {
                    header(HttpHeaders.Authorization, "Bearer $signInToken")
                }
                val user = Json.decodeFromString<User>(response.bodyAsText())
                if (!user.isEquals(currentUser)) {
                    result = CheckResult.wrong("Get method responded with different user information.")
                    return@testApplication
                }
                if (response.status != HttpStatusCode.OK)
                    result = CheckResult.wrong("Status code for a getting existent user should be \"200 OK\"")
            }
        } catch (e: Exception) {
            result = CheckResult.wrong(e.message)
        }
        return result
    }

    @DynamicTest(order = 6)
    fun putDifferentEmail(): CheckResult {
        var result = CheckResult.correct()
        try {
            testApplication {
                val response = client.put("/me") {
                    val newUser = currentUser.copy(email = "different@mail.com")
                    setBody(Json.encodeToString(newUser))
                    header(HttpHeaders.ContentType, ContentType.Application.Json.toString())
                    header(HttpHeaders.Authorization, "Bearer $signInToken")
                }
                if (response.status != HttpStatusCode.BadRequest)
                    result = CheckResult.wrong("You can not change the user's email! Wrong status code.")
            }
        } catch (e: Exception) {
            result = CheckResult.wrong(e.message)
        }
        return result
    }

    @DynamicTest(order = 7)
    fun updateCurrentUser(): CheckResult {
        var result = CheckResult.correct()
        try {
            testApplication {
                val response = client.put("/me") {
                    currentUser = currentUser.copy(name = "newName$time", userType = "newType", address = "newAddress$time")
                    setBody(Json.encodeToString(currentUser))
                    header(HttpHeaders.ContentType, ContentType.Application.Json.toString())
                    header(HttpHeaders.Authorization, "Bearer $signInToken")
                }
                if (response.status != HttpStatusCode.OK)
                    result = CheckResult.wrong("Cannot update user information by put method")
            }
        } catch (e: Exception) {
            result = CheckResult.wrong(e.message)
        }
        return result
    }

    @DynamicTest(order = 8)
    fun getNewExistentUser(): CheckResult {
        var result = CheckResult.correct()
        try {
            testApplication {
                val response = client.get("/me") {
                    header(HttpHeaders.Authorization, "Bearer $signInToken")
                }
                val user = Json.decodeFromString<User>(response.bodyAsText() ?: "")
                if (!user.isEquals(currentUser)) {
                    result =
                        CheckResult.wrong("Get method responded with different user information after updating user info.")
                    return@testApplication
                }
                if (response.status != HttpStatusCode.OK)
                    result = CheckResult.wrong("Status code for a getting existent user should be \"200 OK\"")
                            }
        } catch (e: Exception) {
            result = CheckResult.wrong(e.message)
        }
        return result
    }

    @DynamicTest(order = 9)
    fun deleteExistentUser(): CheckResult {
        var result = CheckResult.correct()
        try {
            testApplication {
                val response = client.delete("/me") {
                    header(HttpHeaders.Authorization, "Bearer $signInToken")
                }
                if (response.status != HttpStatusCode.OK)
                    result = CheckResult.wrong("Status code for a deleting existent user should be \"200 OK\"")
            }
        } catch (e: Exception) {
            result = CheckResult.wrong(e.message)
        }
        return result
    }

    @DynamicTest(order = 10)
    fun deleteNonExistentUser(): CheckResult {
        var result = CheckResult.correct()
        try {
            testApplication {
                val response = client.delete("/me") {
                    header(HttpHeaders.Authorization, "Bearer $signInToken")
                }
                if (response.status != HttpStatusCode.NotFound)
                    result = CheckResult.wrong("Status code for a deleting non-existent user should be \"404 Not Found\"")
            }
        } catch (e: Exception) {
            result = CheckResult.wrong(e.message)
        }
        return result
    }

    @DynamicTest(order = 11)
    fun getDeletedUser(): CheckResult {
        var result = CheckResult.correct()
        try {
            testApplication {
                val response = client.get("/me") {
                    header(HttpHeaders.Authorization, "Bearer $signInToken")
                }
                if (response.status != HttpStatusCode.BadRequest)
                    result = CheckResult.wrong("Status code for a getting deleted user should be \"400 Bad Request\"")
            }
        } catch (e: Exception) {
            result = CheckResult.wrong(e.message)
        }
        return result
    }

    @DynamicTest(order = 12)
    fun checkDeletedCredentials(): CheckResult {
        var result = CheckResult.correct()
        try {
            testApplication {
                val response = client.post("/signup") {
                    setBody(Json.encodeToString(currentCredentials))
                    header(HttpHeaders.ContentType, ContentType.Application.Json.toString())
                }
                if (response.status != HttpStatusCode.OK)
                    result = CheckResult.wrong("Unable to signup after deleting user information. Did you forget to delete user credentials?")
            }
        } catch (e: Exception) {
            result = CheckResult.wrong(e.message)
        }
        return result
    }
}