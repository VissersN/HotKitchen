package hotkitchen.plugins

import com.auth0.jwt.JWT
import com.auth0.jwt.algorithms.Algorithm
import io.ktor.http.*
import io.ktor.server.application.*
import io.ktor.server.request.*
import io.ktor.server.response.*
import io.ktor.server.routing.*
import hotkitchen.*
import io.ktor.server.auth.*
import io.ktor.server.auth.jwt.*
import io.ktor.util.pipeline.*
import kotlinx.serialization.json.Json
import kotlinx.serialization.Serializable
import java.util.*
import kotlinx.serialization.*

class InvalidEmailException(message: String) : RuntimeException(message)
class InvalidPasswordException(message: String) : RuntimeException(message)
class notAuthorizedException(message: String) : RuntimeException(message)

@Serializable
data class ApiResponse(val status: String)

fun Application.configureRouting() {
    routing {

        get("/") {
            call.respondText("Hello World!")
        }

        post("/signup") {
            try {
                val requestSignupData = call.receive<RequestSignupData>()
                if (!checkEmailPassword(requestSignupData.email, requestSignupData.password)) {
                    return@post
                }
                insertDataIntoDatabase(requestSignupData)
                createToken(requestSignupData.email, requestSignupData.userType)
                println("Successfully signed up ${requestSignupData.email}")
            } catch (e: Exception) {
                e.printStackTrace()
                val response = ApiResponse("User already exists")
                call.respond(HttpStatusCode.Forbidden, response)
            }
        }
        post("/signin") {
            try {
                println("Signing in")
                val requestSignInData = call.receive<RequestSignInData>()
                println("${requestSignInData.email} ${requestSignInData.password}")
//                if (!checkEmailPassword(requestSignInData.email, requestSignInData.password)) {
//                    return@post
//                }
                val checkedUser = checkIfUserExists(requestSignInData)
                if (checkedUser != null) {
                    createToken(checkedUser.email, checkedUser.userType)
                    println("Signed in ${requestSignInData.email}")
                } else throw notAuthorizedException("")
            } catch (e: notAuthorizedException) {
                val response = ApiResponse("Invalid email or password")
                call.respond(HttpStatusCode.Forbidden, response)

            }
        }
        authenticate("myAuth") {
            get("/validate") {
                val principal = call.principal<JWTPrincipal>()
                val userType = principal!!.payload.getClaim("userType").asString()
                val email = principal.payload.getClaim("email").asString()
                val response = ("Hello, ${userType} $email")
                println(response)
                call.respond(HttpStatusCode.OK, response)
            }

        }

    }
}

private suspend fun PipelineContext<Unit, ApplicationCall>.checkEmailPassword(
    email: String,
    password: String
): Boolean {
    try {
        val emailRegex = Regex("[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}")
        val passwordRegex = Regex("(?=.*[a-zA-Z])(?=.*\\d)[a-zA-Z0-9]{6,}")
        if (!emailRegex.matches(email)) {
            throw InvalidEmailException("Invalid email")
        }
        if (!passwordRegex.matches(password)) {
            throw InvalidPasswordException("Invalid password")
        }
    } catch (e: InvalidEmailException) {
        val response = ApiResponse("Invalid email")
        call.respond(HttpStatusCode.Forbidden, response)
        return false
    } catch (e: InvalidPasswordException) {
        val response = ApiResponse("Invalid password")
        call.respond(HttpStatusCode.Forbidden, response)
        return false
    }
    return true
}

private suspend fun PipelineContext<Unit, ApplicationCall>.createToken(
    email: String, userType: String
) {
    val token = JWT.create()
        .withAudience(audience)
        .withIssuer(issuer)
        .withClaim("email", email)
        .withClaim("userType", userType)
        .withExpiresAt(Date(System.currentTimeMillis() + 24 * 60 * 60000))
        .sign(Algorithm.HMAC256(secret))
    call.respondText(
        Json.encodeToString(hashMapOf("token" to token)),
        ContentType.Application.Json
    )
}


