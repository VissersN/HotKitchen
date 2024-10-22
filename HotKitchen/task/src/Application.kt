package hotkitchen


import hotkitchen.plugins.configureRouting
import io.ktor.server.application.*
import io.ktor.server.engine.*
import io.ktor.server.netty.*
import java.sql.Connection
import java.sql.DriverManager
import io.ktor.serialization.kotlinx.json.*
import kotlinx.serialization.Serializable
import io.ktor.server.plugins.contentnegotiation.*
import io.ktor.server.auth.*
import io.ktor.server.auth.jwt.*
import com.auth0.jwt.JWT
import com.auth0.jwt.algorithms.Algorithm
import hotkitchen.plugins.ApiResponse
import io.ktor.http.*
import io.ktor.server.request.*
import io.ktor.server.response.*
import io.ktor.server.routing.*
import kotlinx.serialization.*
import kotlinx.serialization.json.Json
import java.util.*

const val secret = "secret"
const val issuer = "http://0.0.0.0:28852/"
const val audience = "http://0.0.0.0:28852/signin"
const val myRealm = "Access to 'page'"

fun main(args: Array<String>) {

    embeddedServer(Netty, port = 28852, host = "0.0.0.0", module = Application::module)
        .start(wait = true)

}

fun Application.module(testing: Boolean = false) {
    install(ContentNegotiation) {
        json()
    }
    install(Authentication) {
        jwt("myAuth") {
            realm = myRealm
            verifier(
                JWT
                    .require(Algorithm.HMAC256(secret))
                    .withAudience(audience)
                    .withIssuer(issuer)
                    .build()
            )
            validate { credential ->
                if (credential.payload.getClaim("email").asString() != "") {
                    JWTPrincipal(credential.payload)
                } else {
                    null
                }
            }
            challenge { defaultScheme, realm ->
                call.respond(HttpStatusCode.Unauthorized)
            }
        }
    }
    configureRouting()

}

fun getConnection(): Connection {
    val url = "jdbc:postgresql://localhost:5432/postgres"
    val user = "postgres"
    val password = "14032010"

    return DriverManager.getConnection(url, user, password)
}

@Serializable
data class RequestSignupData(
    val email: String,
    val userType: String,
    val password: String
)

@Serializable
data class RequestSignInData(
    val email: String,
//    val userType: String,
    val password: String
)

fun insertDataIntoDatabase(requestSignupData: RequestSignupData) {
    testDatabaseConnection()
    try {
        val connection = getConnection()

        connection.use {

            val statement =
                it.prepareStatement("INSERT INTO \"Users\".\"Users\" (email, userType, password) VALUES (?, ?, ?)")
            statement.setString(1, requestSignupData.email)
            statement.setString(2, requestSignupData.userType)
            statement.setString(3, requestSignupData.password)
            statement.executeUpdate()
        }
    } catch (e: Exception) {
        e.printStackTrace()
        throw e
    }

}

data class User(val email: String, val userType: String)

fun checkIfUserExists(requestSignInData: RequestSignInData): User? {

    var dbwaarde: String? = null
    val connection = getConnection()
    connection.use {
        val statement = it.prepareStatement("SELECT password, userType, email FROM \"Users\".\"Users\" where email = ?")
        statement.setString(1, requestSignInData.email)
        val resultSet = statement.executeQuery()
        if (resultSet.next()) {
            dbwaarde = resultSet.getString("password")
        }
        if (requestSignInData.password == dbwaarde) {
            val userEmail = resultSet.getString("email")
            val userType = resultSet.getString("userType")
            println(userType)
            return User(userEmail, userType)
        } else return null
    }
}


fun testDatabaseConnection() {
    try {
        val connection = getConnection()
        println("Verbinding succesvol")
        connection.close()
    } catch (e: Exception) {
        e.printStackTrace()
    }
}