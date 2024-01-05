<?php

namespace App\Http\Controllers\Api;

use App\Http\Controllers\Controller;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Cookie;
use Symfony\Component\HttpFoundation\Response;

//MODELS

use App\Models\User;

class AuthController extends Controller
{
    public function register(Request $request){


        //DATA VALIDATE
        $request->validate([
            'name' => 'required',
            'lastname' => 'required',
            'role' => 'required',
            'phone' => 'required',
            'email' => 'required|email|unique:users',
            'password' => 'required|confirmed'
        ]);

        $user = new User();
        $user->name = $request->name;
        $user->lastname = $request->lastname;
        $user->role = $request->role;
        $user->phone = $request->phone;
        $user->email = $request->email;
        $user->password = Hash::make($request->password);
        $user->save();


        return response($user, Response::HTTP_CREATED);
    }

    public function login(Request $request){
        
        //CREDENTALS VALIDATE
        $credentials = $request->validate([
            'email' => ['required', 'email'],
            'password' => ['required']
        ]);

        if(Auth::attempt($credentials)){
            $user = Auth::user();
            $token = $user->createToken('token')->plainTextToken;
            $cookie = cookie('cookie_token', $token, 60*24);
            return response(["token"=>$token], Response::HTTP_OK)->withoutCookie($cookie);
        } else {
            return response(["message" => "Credenciales Invalidas D:"], Response::HTTP_UNAUTHORIZED);
        }

    }

    public function userProfile(Request $request){
        return response()->json([
            "message"=>"Perfil OK :D",
            'userData' => auth()->user()
        ], Response::HTTP_OK);
    }
    //Prueba

    public function logout(){
        $cookie = Cookie::forget('cookie_token');
        return response(["message" => "Sesion cerrada"], Response::HTTP_OK)->withCookie($cookie);
    }

    
}
