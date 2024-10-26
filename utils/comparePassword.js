import bcrypt from "bcryptjs";



export default async function comparePassword( enteredPassword, storedPassword ){
    return bcrypt.compareSync( enteredPassword, storedPassword )
}